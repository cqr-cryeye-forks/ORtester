#!/usr/bin/python
import json
import os
import pathlib
from typing import Final

import requests
import tldextract
import signal
import warnings
from optparse import OptionParser
import urllib3


def main():
    all_data = []
    if options.url is None:
        parser.print_help()
        exit()

    info = tldextract.extract(URL)
    domain_name = info.registered_domain
    payloadlist = open("payloads.list", encoding="latin-1").readlines()
    newlist = open("all.list", "w")
    for line in payloadlist:
        if line.count("example") == 1 or line.count("example") == 2:
            l = line.replace("example.com", domain_name)
            newlist.write(l)
        else:
            newlist.write(line)
    newlist.close()

    # Open file
    with open(file_all_list) as f:
        for payload in f:
            payloadF = payload.strip()
            urlF = options.url + payloadF
            print(urlF)

            # Get the response.
            try:
                response = requests.get(urlF, verify=False)
                # ===Process to find an open redirect===.
                if response.history:
                    # Compare the destination url with Bing's url.
                    if (
                            str(response.url)[0:19] == "http://www.bing.com"
                            or str(response.url)[0:20] == "https://www.bing.com"
                    ):
                        print("Open Redirect Vulnerability found!")
                        print("Redirected to: " + response.url)
                        print("Payload ---> " + payloadF)
                        data_find = {
                            "msg": "Open Redirect Vulnerability found",
                            "Redirected_to": response.url,
                            "Payload": payloadF,
                        }
                        all_data.append(data_find)
                    else:
                        print("Redirected to: " + response.url)
                        data_find = {
                            "Redirected_to": response.url
                        }
                        all_data.append(data_find)
                else:
                    print("Request was not redirected. Check manually because it might be a redirect using javascript. \n")
            except requests.exceptions.ConnectionError:
                print("ConnectionError")
            except urllib3.exceptions.LocationParseError:
                print("LocationParseError")
            except requests.exceptions.InvalidURL:
                print("InvalidURL")
        return all_data


# Press ctrl+c to finish
def ctrl_c(signum, rfm):
    print("\nSee you soon!\n")
    exit()


if __name__ == '__main__':
    os.system("clear")
    warnings.filterwarnings("ignore")

    file_all_list: Final[pathlib.Path] = pathlib.Path(__file__).parent / "all.list"
    usage = "Usage: python %prog [-h] -u 'URL' -f [file]"

    parser = OptionParser(usage=usage)
    parser.add_option("--url", dest="url", help="target URL")
    parser.add_option("--output", help="output save in json")

    (options, args) = parser.parse_args()
    URL: str = options.url
    output: str = options.output

    MAIN_DIR: Final[pathlib.Path] = pathlib.Path(__file__).parent
    output_json: Final[pathlib.Path] = MAIN_DIR / output

    signal.signal(signal.SIGINT, ctrl_c)
    
    ALL_DATA = main()
    
    if ALL_DATA == []:
        ALL_DATA = {
            "RESULT": "No Open Redirect Found!"
        }
    with open(output_json, "w") as jf:
        json.dump(ALL_DATA, jf, indent=2)
