# Solving a Set Cover Problem in Cloud IAM on GCP

## What is This?

This repo contains a Jupyter Notebook (specifically targeting Python 3.6+) which solves a [Set Cover Problem](https://en.wikipedia.org/wiki/Set_cover_problem): how many Google Cloud IAM roles are required to convey every possible unique IAM permission in GCP?

This is covered in a blog post, and is just the practical application of a greedy algorithm to get an answer to that question, which originally came from a customer seeking every permission.

To be clear, it is not a recommended best practice to grant *every* possible role, but to grant by the policy of [least privilege](https://cloud.google.com/iam/docs/using-iam-securely#least_privilege).

## Requirements

* Python 3.6+
* [Jupyter](https://jupyter.org/install)
* [google-api-python-client](https://github.com/googleapis/google-api-python-client)


## Install

Getting up and running *could* be as simple as the below steps depending on your OS.  Take a look at each of the requirements' installation instructions for further guidance.

Git clone:
```
git clone https://github.com/angstwad/set-cover-iam-roles
cd set-cover-iam-roles
```

Install:
```
pip3 install jupyter[notebook] google-api-python-client
```

Running:
```
jupyter notebook
```

## Disclaimer

This is not an official Google product.
