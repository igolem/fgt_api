#!/usr/local/bin/python3

# file: fgt_api.py
# author: jason mueller
# created: 2018-12-26
# last modified: 2018-02-20

# purpose:
# FortiGate API module for use with token-based authentication

# notes:
# this is a work in progress and not ready for production use.
# use at your own risk.
# this is primarily an exercise in improving my Python skills through a practical
#   application
# the API class(es) have some basic input checking, but only to protect the script from
#   blowing up,
#   not to make sure you have a successful API query
#   and not to save your bacon when you start mucking with custom headers and parameters
# it is assumed that your main script will do the necessary normalization and validation
#   required to make successful queries and to validate responses
# i created net_eng.py, which has some subroutines for validating data
#   and I will create some in this module for validating API specific elements
#   but the work of validation is outside the scope of this module
# the fgt_api_token class object has no problem making an invalid query for you :-)
# i am not designing for http use... only https... sorry.


# python version: 3.7.2

import requests
import urllib3


# fgt_api_token
# class designed for making API queries against FortiOS using token-based authentication
# created: 2018-12-26
# last modified: 2018-02-01
class fgt_api_token:
    def __init__(self, name, host, token):
        self.name = name
        self.host = host
        self.token = token
                
        self.port = '443'
        self.vdom = 'root'
        self.cert_verify = False
        self.timeout = 3

        # set default parameters/headers for HTTP request
        self.url_params = {'vdom': self.vdom}
        # set token in HTTP header, so URL can be displayed without showing token
        self.http_headers = {'Authorization': 'Bearer ' + self.token}        

        # set URL bases for CMDB and monitor queries
        self.cmdb_base = 'https://' + self.host + ':' + self.port + '/api/v2/cmdb/'
        self.monitor_base = 'https://' + self.host + ':' + self.port + '/api/v2/monitor/'
        self.set_paths(self.cmdb_base, self.monitor_base)

    def set_paths(self, cmdb_base, monitor_base):
        self.cmdb_addr = cmdb_base + 'firewall/address/'
        self.cmdb_policy = cmdb_base + 'firewall/policy/'
        self.monitor_policy = monitor_base + 'firewall/policy/'

   # set vdom
   # "vdom" data type is string; multiple VDOMs separated by commas with no spaces
   # change this to list?
    def set_vdom(self, vdom):
        if type(vdom) is str:
            self.vdom = vdom
            self.url_params['vdom'] = self.vdom
            try:
                del url_params['global']
            except:
                return

   # set global
   # API responses include information for all vdoms where user has appropriate rights
    def set_global(self):
        self.url_params['global'] = 1
        try:
            del self.url_params['vdom']
        except:
            return

    # set port
    # "port" data type is integer
    def set_port(self, port):
        try:
            if int(port) > 0 and int(port) < 65536:
                self.port = str(port)
                self.cmdb_base = ('https://' + self.host + ':' + self.port +
                                  '/api/v2/cmdb/')
                self.monitor_base = ('https://' + self.host + ':' + self.port +
                                     '/api/v2/monitor/')
                self.set_paths(self.cmdb_base, self.monitor_base)
        except:
            return

    # set certificate verification
    # "cert_verify" data type is boolean
    def set_sslverify(self, cert_verify):
        if type(cert_verify) is bool:
            self.cert_verify = cert_verify

    # set HTTP response timeout
    # "timeout" data type is integer
    def set_timeout(self, timeout):
        if type(timeout) is int:
            self.timeout = timeout
    
    # set with_meta in URL parameters to include meta data in in API response
    def set_metadata(self):
        self.url_params['with_meta'] = 1
    
    # unset with_metadata
    def unset_metadata(self):
        try:
            del self.url_params['with_meta']
        except:
            return

    # set skip in URL parameters to exclude skipped properties in API response
    def set_skip(self):
        self.url_params['skip'] = 1
    
    # unset skip for URL parameters
    def unset_skip(self):
        try:
            del self.url_params['skip']
        except:
            return

    # arbitrarily set HTTP URL parameters (be careful, with great power...)
    # "custom_params" data type is dict; 
    def set_params(self, custom_params):
        if type(custom_params) is dict:
            for param_name in custom_params.keys():
                self.url_params[param_name] = custom_params[param_name]

    # arbitrarily delete HTTP URL parameters (be careful, with great power...)
    # "del_params" data type is a list; 
    def del_params(self, del_params):
        if type(custom_params) is list:
            for param_name in del_params:
                try:
                    del self.url_params[param_name]
                except:
                    continue

    # arbitrarily set HTTP headers (be careful, with great power...)
    # "custom_headers" data type is dict; 
    def set_headers(self, custom_headers):
        if type(custom_headers) is dict:
            for header_name in custom_headers.keys():
                self.http_headers[header_name] = custom_headers[header_name]

    # arbitrarily delete HTTP headers (be careful, with great power...)
    # "del_headers" data type is a list; 
    def del_headers(self, del_headers):
        if type(del_headers) is list:
            for header_name in del_headers.keys():
                try:
                    del self.http_headers[header_name]
                except:
                    continue

    # set API filter values in HTTP parameters
    # "filter" data type is dict in format {FILTER:OPERATOR}
    # valid operators are "and" and "or"
    def set_filter(self, filters):
        if type(filters) is dict and len(filters.keys()) > 0:
            lc = 0
            for filter in filters.keys():
                try:
                    if filters[filter] in ['or','and'] and lc > 0:
                        if filters[filter] == 'or':
                            filter_text = filter_text + ',filter=' + filter
                        else:
                            filter_text = filter_text + '&filter=' + filter
                    elif lc == 0:
                        filter_text = filter 
                    lc += 1
                except:
                    continue
            self.url_params['filter'] = filter_text

    # remove filter from HTTP parameters
    def unset_filter(self):
        try:
            del self.url_params['filter']
        except:
            return

    # set token in URL and remove from HTTP header
    def url_token(self):
        try:
            self.url_params['access_token'] = self.token
            del self.http_headers['Authorization']
        except:
            return
                
    # set token in HTTP header and remove token from URL
    # allows move back to header-based token auth after setting URL token auth
    def header_token(self):
        try:
            self.http_headers['Authorization'] = 'Bearer ' + self.token
            del self.url_params['access_token']
        except:
            return

    # disable TLS warnings if cert verify is off; else enable warnings
    # set per API request, since multiple FGTs in same script may have diff requirements
    def set_url_warn(self, cert_verify):
        if not cert_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            warnings.resetwarnings()

            
    #####
    # define set of generalized API methods for supported HTTP methods
    # HTTP get, post, put, and delete
    #####

    # send HTTP get request to FGT API
    def api_get(self, api_url):
        try:
            self.set_url_warn(self.cert_verify)
            response = requests.get(api_url,
                                    params = self.url_params,
                                    headers = self.http_headers,
                                    verify = self.cert_verify,
                                    timeout = self.timeout)
            return response
        except:
            return None

    # send HTTP post request to FGT API
    def api_post(self, api_url, json_data):
        try:
            self.set_url_warn(self.cert_verify)
            response = requests.post(api_url,
                                     params = self.url_params,
                                     headers = self.http_headers,
                                     verify = self.cert_verify,
                                     json = json_data,
                                     timeout = self.timeout)
            return response
        except:
            return None

    # send HTTP put to FGT API
    def api_put(self, api_url):
        try:
            self.set_url_warn(self.cert_verify)
            response = requests.put(api_url,
                                    params = self.url_params,
                                    headers = self.http_headers,
                                    verify = self.cert_verify,
                                    timeout = self.timeout)
            return response
        except:
            return None

    # send HTTP delete to FGT API
    def api_delete(self, api_url):
        try:
            self.set_url_warn(self.cert_verify)
            response = requests.delete(api_url,
                                       params = self.url_params,
                                       headers = self.http_headers,
                                       verify = self.cert_verify,
                                       timeout = self.timeout)
            return response
        except:
            return None


    #####
    # define specific task-based API calls
    #####

    #####
    # address object cmdb functions
    #####
    
    # retrieve all defined address objects
    def show_addresses(self):
        api_url = self.cmdb_addr
        response = self.api_get(api_url)
        return response

    # retrieve specific named address object
    def get_address(self, addr_name):
        if type(addr_name) is str:
            api_url = self.cmdb_addr + addr_name
            response = self.api_get(api_url)
            return response

    # add an address to a FortiGate
    # address object must be a valid dict
    def add_address(self, addr_object):
        if type(addr_object) is dict:
            # set URL for adding an address object
            api_url = self.cmdb_addr
            # call generalized API post method
            response = self.api_post(api_url, addr_object)
            return response

    # delete an address object on a FortiGate
    def del_address(self, addr_name):
        if type(addr_name) is str:
            api_url = self.cmdb_addr + addr_name
            response = self.api_delete(api_url)
            return response
        else:
            return None
    

    #####
    # policy cmdb functions
    #####
    
    # show all policies
    def show_policies(self):
        api_url = self.cmdb_policy
        response = self.api_get(api_url)
        return response

    # get an individual policy
    def get_policy(self, policy_index):
        if type(policy_index) is int:
            policy_index = str(policy_index)
            api_url = self.cmdb_policy + policy_index
            response = self.api_get(api_url)
            return response

    # add a policy to a FortiGate
    # policy_definition must be dict
    def add_policy(self, policy_definition):
        if type(policy_definition) is dict:
            api_url = self.cmdb_policy
            response = self.api_post(api_url, policy_definition)
            return response

    # query FortiGate policy based on filter criteria provided
    # filter must be a dict with in the format {SEARCHTEXT: OPERATOR};
    #   None can be used in place of operator for first search term
    def search_policy(self, policy_filter):
        if type(policy_filter) is dict:
            api_url = self.cmdb_policy
            # add filters to URL parameters
            self.set_filter(policy_filter)
            response = self.api_get(api_url)
            # remove filter parameter
            del self.url_params['filter']
            return response
        
    # move a policy on a FortiGate
    # index is "mkey"; ref_index is the index of the policy to move around
    def move_policy(self, index, ref_index, move_type):
        if (type(index) is int and type(ref_index) is int and 
            move_type in ['before', 'after']):
            index = str(index)
            ref_index = str(ref_index)
            api_url = self.cmdb_policy + index
            # add move parameters to URL
            self.url_params['action'] = 'move'
            self.url_params[move_type] = ref_index
            response = self.api_put(api_url)
            # remove move parameters from URL
            del self.url_params['action']
            del self.url_params[move_type]
            return response            

    # delete a policy on a FortiGate
    def del_policy(self, index):
        index = str(index)
        api_url = self.cmdb_policy + index
        response = self.api_delete(api_url)
        return response

    #####
    # monitor branch of API calls
    #####

    # get firmware info from a FortiGate
    def get_firmware(self):
        api_url = self.monitor_base + 'system/firmware/'
        response = self.api_get(api_url)
        return response


# validate fortigate country value
# created: 2019-01-07
# last modified: 2019-02-10
def valid_fgt_cn(addr_country):
    
    # valid fortigate country codes as of 2019-01-07
    valid_cn_list = ['ZZ', 'O1', 'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO',
                     'AQ', 'AR', 'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD',
                     'BE', 'BF', 'BG', 'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ',
                     'BR', 'BS', 'BT', 'BV', 'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF',
                     'CG', 'CH', 'CI', 'CK', 'CL', 'CM', 'CN', 'CO', 'CR', 'CU', 'CV',
                     'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ', 'DK', 'DM', 'DO', 'DZ', 'EC',
                     'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI', 'FJ', 'FK', 'FM', 'FO',
                     'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH', 'GI', 'GL', 'GM',
                     'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY', 'HK', 'HM',
                     'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO', 'IQ',
                     'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI',
                     'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI',
                     'LK', 'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME',
                     'MF', 'MG', 'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR',
                     'MS', 'MT', 'MU', 'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE',
                     'NF', 'NG', 'NI', 'NL', 'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA',
                     'PE', 'PF', 'PG', 'PH', 'PK', 'PL', 'PM', 'PN', 'PR', 'PS', 'PT',
                     'PW', 'PY', 'QA', 'RE', 'RO', 'RS', 'RU', 'RW', 'SA', 'SB', 'SC',
                     'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK', 'SL', 'SM', 'SN', 'SO',
                     'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC', 'TD', 'TF', 'TG',
                     'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT', 'TV', 'TW',
                     'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE', 'VG',
                     'VI', 'VN', 'VU', 'WF', 'WS', 'XK', 'YE', 'YT', 'ZA', 'ZM', 'ZW']
    
    if addr_country in valid_cn_list:
        valid_cn = True
    else:
        valid_cn = False

    return valid_cn        


# receive fgt color value, change all invalid colors to 0
# created: 2019-01-06
# last modified: 2019-01-06
def color_std(color_index):
    try:
        color_index = int(color_index)
        if (color_index < 0 or color_index > 32):
            color_index = 0                                
    except:
        color_index = 0

    return color_index
