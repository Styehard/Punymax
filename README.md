![](https://user-images.githubusercontent.com/12640176/96775541-f42e9a00-13e7-11eb-925c-2afe515c9629.png)
## **PUNYMAX** - A homograph phishing protection tool

A tool to protect you from homograph phishing attacks.



## What you will need

1. A running server with a MariaDB database with a list of trusted host-names.
2. Google Chrome
3. Tesseract 

## Install

1. Clone this repository.
2. Move the `Punymax_analysis.py` file to your server. 

2. Change the marked things with **CHANGE:**  in the in the `background.js` file.
3. Change the marked things with **CHANGE:** in the `Punymax_analysis.py` file. (tesseract path and database parameters)
4. Visit [chrome://extensions/](chrome://extensions/)
5. Click **Load unpacked** and choose the root of this repository (the local folder you downloaded)



## Usage

There are two ways of using the script: 

1. Through web navigation: the extension detects when you access a website with Unicode characters or is encoded in puny-code. 

2. With the command line:

   ```Bash
   py .\Punymax_analysis.py -i imput_txt_file -o output_csv_file  -v[0-2] -p[0-6]
   ```

   ```Bash
   py .\PunyMax_analysis.py -s goog?e.com -v0 -p2
   ```

   

