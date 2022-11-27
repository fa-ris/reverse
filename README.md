This repository contains four (4) different reverse engineering tools. Two (2) of them are IDA Pro plugins, and the other two (2) are Pin tools, built for dynamic program analysis.

The IDA Pro plugins are built for static code analysis. Specifically, they entail use-define chain and data dependence programs, both yielding .DOT graph files as outputs. Be sure to add these files to the IDA directory before use! Also, both hotkeys are listed as Alt-P currently -- to use both plugins together, be sure to change one of the hotkeys to a different unused one.

The Pin tools are built for dynamic program analysis. They entail control flow tracing and control dependence programs, both also yielding .DOT graph files as outputs. To run the Pin tools, simply run the following on command line (making sure you are in a safe environment if analyzing malware):

<absolute path of Pin (the actual Pin software)> -t <absolute Pin tool path>\MyPinTool.dll --<absolute path of the program we want to analyze using tool>

For example:
c:\pin\pin.exe -t Debug\MyPinTool.dll --calc.exe

All output graphs are directed! :)
