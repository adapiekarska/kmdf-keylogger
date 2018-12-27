
# KeyLogger

## Description
Simple Key Logger KMDF Driver.

## Author
Adrianna Piekarska
Based on Microsoft's [kbfiltr](https://github.com/Microsoft/Windows-driver-samples/tree/master/input/kbfiltr) driver.

## Installation
For installation guide, see instructions on the [kbfiltr's page](https://github.com/Microsoft/Windows-driver-samples/tree/master/input/kbfiltr).

## Description
Driver that hooks itself between the KbdClass driver and i8042prt driver and intercepts keystrokes.

Intercepted data is written to a log file, which default location is `C:\log.txt`. Writing to the file is being done by the separate system worker thread. The driver creates the worker and later uses it whenever there is enough data in the buffer. The trigger point for writing the data can be set by modifying the `LOG_TRIGGER_POINT` define directive.

Because the keystrokes are written to file in the blocks of fixed size, there is a possibility of the logger being unable to record last keystrokes in case of driver being unloaded when the buffer is not full. This problem can be overcome by setting `LOG_TRIGGER_POINT` to `1`. However then disk access frequency increases.

The log file is protected from accessing by any user by configuring the proper Discretionary Access Control List. This however does not prevent system administrator to take ownership of the file. But even then, the file cannot be accessed by anyone during the lifetime of the driver as the driver keeps the handle to the file open and unaccessible to other processes (by specyfing the exclusive access to the created file).

Due to the fact that the driver unload routine in case of PnP drivers can be called at any time after the device is removed (and it seems that it is called only when the new driver is being loaded in the place of the previous one), the permissions of the log file must be reset manually so that the contents of the log can be examined.
  
