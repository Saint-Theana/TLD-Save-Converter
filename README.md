# TLD-Save-Converter
convert the long dark game save data into json format.

# Notice
Modifying save data might cause unknown issues. You should back up your save data before attempting any modifications. If you lose your save file or mess up your game after using this code to modify save data, I am not responsible for it.


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


