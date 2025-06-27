# TLD-Save-Converter
convert the long dark game save data into json format.

# How to use
usage: test.py [-h] -i INPUT -o OUTPUT (-e | -d)  
optional arguments:<br> 
  -h, --help show this help message and exit.<br>  
  -i INPUT, --input INPUT define input file.<br>     
  -o OUTPUT, --output OUTPUT define out put file.<br> 
  -e, --encode encode json into save data.<br>
  -d, --decode decode json from save data.<br>
example:<br>
python3 converter.py -i sandbox1 -d -o decoded.json<br>
python3 converter.py -o sandbox1_new -e -i decoded.json<br>


