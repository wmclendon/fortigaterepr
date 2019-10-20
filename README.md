# fortigaterepr

NOTE:  This should be considered ALPHA!

Built off of Fortinet's fortiosapi library to provide an abstraction and representation of various operational state data of a Fortigate Device.  Currently most operational data is modeled in a sub-classed Pandas Dataframe, and the Dataframe itself can be manipulated like any other Dataframe for manipulation of the output.  Has some helper methods that more or less wrap some of the methods in the fortiosapi library -- most (all?) of the parameters that library accepts are passed through from the FortigateDevice Class, with the same defaults.  The data is sub-classed to allow for some helper methods to clean up the data and also to provide some canned output filtering options like removing certain often-unnecessary columns from printouts, etc.

To gather data from the device, use one of the 'get' methods available such as `get_interfaces()`.  This returns the result and also stores the result as a property of the class instance - i.e. `dev.interfaces`

In general all of the data returned from the device API is stored in the DataFrame, though there is some data cleanup that can occur (i.e. converting epoch timestamp to readable date/time, replacing NaNs with "None" or "N/A", etc.).  Often the number of columns is quite large, and much of the data is not useful most of the time, so each DataFrame has a `get()` method that will return a copy of the DataFrame with certain columns removed (depends upon the table).  If the full DataFrame is needed, you can just reference the appropriate class instance property - i.e. `dev.interfaces`

## Basic Use

Simple example usage:

```python
from fortigaterepr.fortigaterepr import FortigateDevice
dev = FortigateDevice(
    "192.0.2.50",
    username="username",
    password="password",
    apitoken="secretapitoken",
    verify=False,
)

if not dev.restapilogin():
    print("Error authenticating to API - exiting!")
    sys.exit(1)

interface_data = dev.get_interfaces()

# print entire interface_data DataFrame:
print(interface_data)

# print a generally more useful subset:
print(interface_data.get())
```

## TODO

* Unit Tests
* more state data gathering / representation
  * Address Book Objects
  * format Facts Dictionary into simple DataFrame
  * how to add route table size?  as own dataframe, or somehow as part of Route Table DataFrame?
* methods for other output formats -- i.e. a `to_html()` or `to_json()` method that takes all the stored data and writes it to HTML or JSON stdout or to a file.
* other?
