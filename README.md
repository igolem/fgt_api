# fgt_api

__fgt_api.py__ is a Python module with some functions for working with the FortiGate API using token-based authentication.

There are no explicit or implied guarantees or warranties with this module.
See required Python modules below.


-----
## The Basics

* The __fgt_api.py__ module is a work in progress with major completion targeted for EOY 2019.

* The module assumes the following:
    * HTTPS operation (no HTTP)
    * Target FGT has a defined API user with a token (no user login)
    * Input validation is handled by the logic of your script, not the fgt_api_token() class.

* Documentation is planned, but not likely prior to EOY 2019.

* Some functions will be added to the module that will be helpful in input validation that are specific to FortiGates.

* Some general input validation functions can be found in my net_eng.py module.

-----
## Required Python modules:
* requests
* urllib3
