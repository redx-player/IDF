# Image Digital Forensic tool - [IDF](https://github.com/Red-x-player/IDF.git)

This tool was designed to make a full analysis for images and give a full report
<br> IDF can help CTF player or cybersecurity engineer to perform tasks faster and more quickly
by using some tools like binwalk,foremost,exiftool,stegsolve,etc

### How the tool works
* check from file type
* convert bytes to strings > 2strings.txt
* extrect image meta data > metaData.txt
* using foremost to extract hidden files
* using binwalk to extract hidden files
* using stegsolve.jar to play in image colors
* reverse image bytes
* perform XOR to image bytes in a certain range from user
* perform AND and to image bytes In a certain range from user
* crack jpg image with steghide

### Installation:
```
git clone https://github.com/Red-x-player/IDF.git
cd IDF
pip install -r requirements.txt
chmod +x stegsolve.jar
```
### Running:
```
python IDF.py <image/file>
```
### Version
IDF v1.0
