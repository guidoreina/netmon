qevents
=======
Qt program which displays the TCP connections from a JSON file containing events.

* Start `qevents`.
* Click on `File` and then on `Open`.
* Open the JSON file containing the events produced by `evreader` using as output `json`.
* The listbox `IP addresses` is filled with all the IP addresses contained in the events file.
* The listbox `Hosts` is filled with all the hostnames contained in the events file.
* If you click on one IP address or on one host, the table below will be filled with all the connections from/to that IP address/host.
* If you click on one of the connections, the table below will be filled with all the payload sizes sent either by the client or by the server.
