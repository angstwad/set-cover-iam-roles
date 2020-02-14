# Copyright 2020 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific languag

"""
This script runs against the GCP IAM API, fetch all roles their descriptions
and writes them to a JSON file. Invoke directly.  Use `--help` to see command
line arguments.
"""

import argparse
import json

from googleapiclient import discovery


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file',
                        type=argparse.FileType('w'),
                        default=open('roles.json', 'w'),
                        help='File to write role data to as JSON. '
                             'Default: roles.json')
    return parser.parse_args()


def main(args):
    iam = discovery.build('iam', 'v1')

    # Fetch most up to date role list and role descriptions from API
    raw_role_data = {}
    request = iam.roles().list()

    print('Initializing first request for roles.')
    while True:
        print('Executing roles request.')
        response = request.execute()

        for role in response.get('roles', []):
            name = role['name']
            if name not in raw_role_data:
                print(f'Getting details for {name}.')
                raw_role_data[name] = iam.roles().get(name=name).execute()

        print('Building request for more roles.')
        request = iam.roles().list_next(previous_request=request,
                                        previous_response=response)

        if request is None:
            print('Fetched all roles.')
            break

    print(f'Writing data to {args.file.name}.')

    json.dump(raw_role_data, args.file, indent=2)
    args.file.close()

    print('Done')


if __name__ == '__main__':
    args = parse_args()
    main(args)
