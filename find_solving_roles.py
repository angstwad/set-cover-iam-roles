# Copyright 2020 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This script intends to brute force combinations of GCP IAM roles, the
permissions of which, upon computing their set union, equal every possible IAM
permission available.  The purpose is to determine the fewest possible IAM
roles which provides every possible IAM permissions.

There are two steps.  The first step is running the producer, which creates
data files, one per core on the device, of combinations up to the '--num'
command line argument.  As the production of data is slower than the
processing of the data (and is not easily parallelizable), this runs in a
single process.  The next step is where the work is split in order to process
the combinations in the most efficient manner.  A process per core is started,
the core is assigned a file to read, and the combinations are processed until
EOF.  If any combination is found to be a "winner", and comprises all possible
IAM roles, it is immediately written to the --output-dir location as a
<timestamp>_winner.json file.  When all process are complete, a winner
summary is written to the file `winners.json` in the path specified by
--output-dir.
"""

import argparse
import collections
import itertools
import json
import logging
import math
import multiprocessing
import multiprocessing.synchronize
import pathlib
import sys
import threading
import time
import typing

_LOG_FORMAT = "%(levelname)s:%(asctime)s:%(name)s:%(message)s"
logging.basicConfig(stream=sys.stdout, format=_LOG_FORMAT)
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# TODO: fix hardcoded values; calculate total number of combinations dynamically
_n = []
for i in range(1, 16):
    _n.append((math.factorial(39) // math.factorial(39 - i)) //
              math.factorial(i))
TOTAL_COMBINATIONS = sum(_n)


class LazyFileType(argparse.FileType):
    """
    Subclasses `argparse.FileType` in order to provide a way to lazily open
    files for reading/writing from arguments.  Initializes the same as the
    parent, but provides `open` method which returns the file object.

    Usage:
    ```
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', type=LazyFileType('w'))
    args = parser.parse_args()

    with args.f.open() a f:
        for line in foo:
            ...
    ```

    Provides an alternate constructor for use with the `default` kwarg to
    `ArgumentParser.add_argument`.

    Usage:
    ```
    #
    parser.add_argument('-f', type=LazyFileType('w'),
                        default=LazyFileType.default('some_file.txt')
    """

    def __call__(self, string: str) -> None:
        self.filename = string

        if 'r' in self._mode or 'x' in self._mode:
            if not pathlib.Path(self.filename).exists():
                m = (f"can't open {self.filename}:  No such file or directory: "
                     f"'{self.filename}'")
                raise argparse.ArgumentTypeError(m)

        return self

    def open(self) -> typing.IO:
        return open(self.filename, self._mode, self._bufsize, self._encoding,
                    self._errors)

    @classmethod
    def default(cls, string: str, **kwargs) -> None:
        inst = cls(**kwargs)
        inst.filename = string
        return inst


class DirType:
    """
    Meant to be used as an `argparse.ArgumentParser.add_argument` argument
    type or default.  Has a single useful attribute, `path`, which is
    `pathlib.Path` object representing the specified argument the current
    working directory.
    """
    path: pathlib.Path = pathlib.Path.cwd()

    def __init__(self, path: str = None) -> None:
        if path is not None:
            self.path = pathlib.Path(path)
            if not self.path.is_dir():
                raise argparse.ArgumentTypeError(
                    f"'{path}' is not a directory")


def process_data(file: LazyFileType,
                 roles_to_perms: typing.DefaultDict[str, set],
                 perms_counts: typing.DefaultDict[str, int],
                 unique_perms: typing.Set[str]) -> None:
    """ With a roles JSON file produced by `fetch_role_data.py`, takes the
    contents of the file and sets up a few mappings.  Mutates all the mutable
    arguments to the function; returns nothing.

    Args:
        file: JSON raw roles data produced by fetch_role_data.py
        roles_to_perms: mapping of roles to their permissions; populated by
            this func
        perms_counts: mapping of role to the number of permissions it contains;
            populated by this func
        unique_perms: set which will be populated with all unique permissions
    """
    logger.info(f'Reading roles file "{file.filename}".')
    with file.open() as f:
        raw_role_data = json.load(f)

    # Read over each role, inspect the permissions, count the number of
    # permissions of each, and create a set of all unique roles.  This will
    # be used to generate combinations and by the workers as they process
    # combinations.
    logger.info(f'Processing roles.')
    for role_name, role_data in raw_role_data.items():
        for perm in role_data.get('includedPermissions', []):
            roles_to_perms[role_name].add(perm)
            perms_counts[role_name] += 1
            unique_perms.add(perm)

    logger.info(f'Unique roles: {len(roles_to_perms)}')
    logger.info(f'Unique permissions: {len(unique_perms)}')

    logger.info('Sorting roles.')
    roles_sorted_by_perms_asc = sorted(perms_counts.items(), key=lambda x: x[1])

    # Eliminate roles which are subsets of another, drastically reducing the
    # number of combinations
    subset_roles = set()
    for this_role, _ in roles_sorted_by_perms_asc:
        for other_role, other_perms in roles_to_perms.items():
            if this_role == other_role:
                continue

            this_perms = roles_to_perms[this_role]

            if this_perms.issubset(other_perms):
                subset_roles.add(this_role)

    # Remove subset roles from common structures
    for role in subset_roles:
        del roles_to_perms[role]
        del perms_counts[role]

    logger.info(f'Deduped roles: {len(roles_to_perms)}')


def producer(data_dir: DirType,
             num_combinations: int,
             roles_to_perms: typing.Dict[str, set]) -> None:
    """ Evaluates roles_to_perms to create combinations of all the roles
    contained therein. Creates a file per core which contains role
    combinations, a comma-separated list of combinations (using the legend to
    optimize space) per line. Iterates over the combinations, placing one
    combination per file, moving onto the next file continuously until no
    combinations remain.  Combinations are calculated starting from
    `num_combinations`, working to 1 (i.e. 39C15, then 39C14, etc).  Uses
    `multiprocessing.cpu_count()` to determine how many files to create (and
    therefore how many workers to start when checking the combinations) so the
    intent is for this to be run on the machine where the workers will run.

    Args:
        data_dir: directory where the data files are located
        num_combinations: max number of combinations to try from a set
        roles_to_perms: mapping of roles to the permissions they contain
    """
    count = 0
    start = time.time()
    fps: typing.List[typing.IO] = []
    cpu_count = multiprocessing.cpu_count()

    # Rather than dump full role names in our combinations to the file,
    # instead assign a much smaller int value to the role, and log this
    # mapping of int value to role name as the "legend" to a file
    legend = {str(i): r for i, r in enumerate(roles_to_perms)}
    legend_fname = data_dir.path.joinpath('legend.json')

    with open(legend_fname, 'w') as f:
        json.dump(legend, f, indent=2)

    # Create one file per CPU on the system; each file will be assigned on
    # one spawned worker in the worker pool.
    for i in range(cpu_count):
        comb_fname = data_dir.path.joinpath(f'{i}.combination')
        fps.append(open(comb_fname, 'w'))

    logger.info(f'Writing {cpu_count} files.')

    # Start writing across the files, splitting the combinations one at a
    # time across each file, spreading the combos evenly
    for i in range(num_combinations, 0, -1):
        for combination in itertools.combinations(legend, i):
            line = f'{",".join(combination)}\n'
            fps[count % cpu_count].write(line)
            count += 1

            if time.time() - start > 60:
                logger.info(f'Produced {count:,} combinations.')
                start = time.time()

    logger.info('Done.')

    for fp in fps:
        fp.close()


def worker(file: str,
           winner_path: DirType,
           winners: typing.List[typing.Tuple[str]],
           roles_to_perms: typing.Dict[str, set],
           unique_perms: typing.Set[str],
           legend: typing.Dict[str, str],
           counter: multiprocessing.Value,
           lock=multiprocessing.synchronize.RLock) -> None:
    """ The worker process to be started by the worker `multiprocessing.Pool`.
    Reads a file of combinations created by the `producer` function and
    evaluates whether the union of all the permissions for each role equals
    the universe `unique_perms`.  Keeps track of how many combinations it has
    tried since starting, and manages an interval counter, tracking how many
    combinations it has tried every 30 seconds, updating a shared global
    counter passed in as `counter`. If a winning combination is found (one
    that satisfies the universe). it is immediately written to a file in
    `winners_path` and appended to the `winners` list.

    Args:
        file: file of combos (must have been written by `producer` func)
        winner_path: path where winners are written
        winners: list where winning combos are appended
        roles_to_perms: mapping of roles to the permission they contain
        unique_perms: set of unique permissions
        legend: mapping of data file values to role names
        counter: global counter shared by all workers
        lock: lock to be used over the counter
    """
    current = multiprocessing.current_process()
    logger = logging.getLogger(f'Worker{current.name}')
    logger.setLevel(logging.INFO)
    logger.info('Worker starting.')

    last = time.time()
    g_count, int_count = 0, 0

    logger.info(f'Opening {file}.')


    try:
        with open(file) as f:
            for line in f:
                # be sure to strip line endings or we'll never match
                combination = line.strip().split(',')

                # will contain perms of roles in combo
                perms_union = set()

                for role in combination:
                    # roles in the combination are stored using the legend,
                    # so look them up, get perms, add to perms_union
                    perms_union.update(roles_to_perms[legend[role]])

                # We have a winner
                if perms_union == unique_perms:
                    logger.warning(f'Solution found: '
                                   f'{", ".join(combination)}')

                    t = round(time.time() * 1000)
                    fname = winner_path.path.joinpath(f'{t}_winner.json')

                    pretty_combo = [legend[role] for role in combination]

                    # dump immediately so the result is captured even if
                    # process encounters an issue
                    with open(fname, 'w') as f:
                        json.dump({'combo': pretty_combo}, f, indent=2)

                    with lock:
                        winners.append(pretty_combo)

                g_count += 1
                int_count += 1

                # Update the global (all process) counter every 30 secs
                if time.time() - last > 30:
                    last = time.time()
                    with lock:
                        counter.value += int_count
                    int_count = 0
    except KeyboardInterrupt:
        logger.warning('Got KeyboardInterrupt.')
    except Exception as e:
        # Be sure log using the process immediately, otherwise the exc is
        # swallowed up (as we are not using error callbacks
        logger.exception(e, exc_info=True)
        raise

    # Update global counter one last time for accuracy
    with lock:
        counter.value += int_count

    logger.info(f'Terminating. Processed {g_count:,} combinations.')


def process_winners(winner_path: DirType,
                    winners: typing.List[typing.Tuple[str]]) -> None:
    """ Writes a single file summary of all winning combinations found by the
    workers.

    Args:
        winner_path: path to write the winner summary file
        winners: list of winning combinations to summarize
    """
    logger.info('Processing winners.')

    results = collections.defaultdict(list)

    for result in winners:
        results[len(result)].append(result)

    if results:
        fpath = winner_path.path.joinpath(f'winner.json')
        logger.info(f'Writing winners to {fpath.absolute()}.')
        with open(fpath, 'w') as f:
            json.dump(results, f, indent=2)
    else:
        logger.info('No winners.')


def log_counter(counter: multiprocessing.Value) -> None:
    """ Intended to be run as a thread from the parent process. Reads the global
    counter and writes a log entry every 60 seconds.

    Args:
        counter: global worker combinations counter
    """
    while True:
        logger.info(f'Processed {counter.value:,} combinations globally – '
                    f'{(counter.value / TOTAL_COMBINATIONS) * 100:.4f}% '
                    f'complete.')
        time.sleep(60)


def main(args: argparse.Namespace) -> None:
    """ The magic happens here.  Evaluates arguments.  Initializes the shared
    role data mappings.  Invoked `process_data` to process the raw role data
    file. Invokes `producer` and spins up the worker `multiprocessing.Pool` as
    specified by the command line arguments.  Starts the `log_counter`
    thread. Waits for the workers to complete.  Invokes `process_winners` when
    workers complete or `KeyboardInterrupt` is caught.

    Args:
        args: command line arguments namespace
    """
    roles_to_perms: typing.DefaultDict[str, set] = collections.defaultdict(set)
    perms_counts: typing.DefaultDict[str, int] = collections.defaultdict(int)
    unique_perms: typing.Set[str] = set()

    process_data(args.file, roles_to_perms, perms_counts, unique_perms)

    if not args.no_producer:
        producer(args.data_dir, args.num, roles_to_perms)

    if not args.no_worker:
        manager = multiprocessing.Manager()
        pool = multiprocessing.Pool()
        winners = manager.list()
        lock = manager.RLock()
        counter = manager.Value('i', 0)

        with open(args.data_dir.path.joinpath('legend.json')) as f:
            legend: typing.Dict[str, str] = json.load(f)

        # Start one worker for every CPU
        work = []
        for i in range(multiprocessing.cpu_count()):
            fname = args.data_dir.path.joinpath(f'{i}.combination')
            args_ = (fname, args.output_dir, winners, roles_to_perms,
                     unique_perms, legend, counter, lock)
            result = pool.apply_async(worker, args=args_)
            work.append(result)

        # We won't start any more processes
        pool.close()

        # Start a daemon thread (will be killed when the main program exits) to
        # give regular updates about how many combinations have been tried
        t = threading.Thread(target=log_counter, args=(counter,), daemon=True)
        t.start()

        # Wait for the workers to complete and handle KeyboardInterrupts so
        # that the results still end up written to a file
        try:
            pool.join()
        except KeyboardInterrupt:
            try:
                logger.error('Got KeyboardInterrupt; shutting down workers.')
                logger.error('Press Control-C again to stop immediately.')
                process_winners(args.output_dir, winners)
                pool.terminate()  # Sends KeyboardInterrupt to child procs
            except KeyboardInterrupt:
                pool.terminate()
                raise SystemExit('Terminating on KeyboardInterrupt')
        else:
            process_winners(args.output_dir, winners)
        finally:
            logger.info(f'Processed {counter.value:,} combinations globally – '
                        f'{(counter.value / TOTAL_COMBINATIONS) * 100:.4f}% '
                        f'complete.')


def parse_args() -> argparse.Namespace:
    """ Sets up an `argparse.ArgumentParser`, parses the args, returns them.

    Returns: parsed arguments namespace
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',
                        type=LazyFileType(),
                        default=LazyFileType.default('roles.json'),
                        help='JSON file to read role data from. Default: '
                             'roles.json')
    parser.add_argument('-n', '--num',
                        type=int,
                        default=15,
                        help='Max number of combinations to try. Default: 15')
    parser.add_argument('-o', '--output-dir',
                        type=DirType,
                        default=DirType(),
                        help=f'Directory to write winning combinations to. '
                             f'Default: current working directory')
    parser.add_argument('-d', '--data-dir',
                        type=DirType,
                        default=DirType(),
                        help=f'Path to read/write producer data files. '
                             f'Default: current working directory')
    mutex = parser.add_mutually_exclusive_group()
    mutex.add_argument('--no-producer',
                       action='store_true',
                       help='Do not run the producer (uses existing data)')
    mutex.add_argument('--no-worker',
                       action='store_true',
                       help="Do not run the workers (produce only)")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
