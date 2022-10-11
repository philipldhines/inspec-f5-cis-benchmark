# F5 CIS 1.0 Benchmark Inspec Profile

This repository holds the [F5 BIG-IP (F5)](https://f5.com/) [Center for Internet Security (CIS)](https://www.cisecurity.org) [version 1.0 Benchmark](https://www.cisecurity.org/benchmark/f5/) [Inspec](https://www.inspec.io/) Profile.

## Required Disclaimer

This is not an officially supported Google product. This code is intended to help users assess their security posture on the Google Cloud against the CIS Benchmark. This code is not certified by CIS.

## Coverage


## Usage

### Profile Inputs (see `inspec.yml` file)

This profile uses InSpec Inputs to make the tests more flexible. You are able to provide inputs at runtime either via the `cli` or via `YAML files` to help the profile work best in your deployment.

**pro tip**: Do not change the inputs in the `inspec.yml` file directly, either:

- update them via the cli - via the `--input` flag
- pass them in via a YAML file as shown in the `Example` - via the `--input-file` flag

Further details can be found here: <https://docs.chef.io/inspec/inputs/>

### (Required) User Provided Inputs - via the CLI or Input Files

### (Optional) User Provided Inputs
