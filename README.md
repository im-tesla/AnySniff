# AnySniff

**AnySniff** is a C++20 program designed for educational and research purposes to identify the IP addresses of callers via AnyDesk. This tool logs information such as IP address, country, city, and ISP, allowing users to gain insights into caller details during AnyDesk sessions.

## Features

- **Caller IP Sniffing:** Detects the IP address of incoming calls through AnyDesk.
- **Geolocation Information:** Logs country, city, and ISP details based on IP addresses.
- **Efficient Logging:** Ensures that each IP is logged only once to avoid redundant data.

## Installation

1. Clone the repository:
   git clone https://github.com/yourusername/AnySniff.git
2. Open the project in **Visual Studio 2022**.
3. Ensure that the project is set to **C++20** standard in project properties.
4. Build the solution using Visual Studio's built-in compiler.

## Usage

Run the compiled executable from the output directory:
```
.\AnySniff.exe
```
The program will initialize and begin sniffing for caller IPs, logging them along with relevant geolocation data.

## Code Overview

The core components of the program are as follows:

- **Initialization**: Sets up the console handler for clean exit.
- **IP Sniffing**: Continuously sniffs caller IPs, logging new addresses with additional details such as country and ISP.
- **Loop Control**: Maintains a list of already sniffed IPs to avoid duplicate entries.
- **Logging**: Uses a custom debug logger to display information with different levels of importance (INFO, WARNING).

### Example Log Output
```
[2024-11-07 14:41:10] [INFO] Initialized AnyDesk.
[2024-11-07 14:41:10] [INFO] Sniffing caller IP address...
[2024-11-07 14:41:14] [INFO] ---------------
[2024-11-07 14:41:14] [WARNING] New caller IP: xx.xx.xx.xx
[2024-11-07 14:41:14] [WARNING] Country: Poland
[2024-11-07 14:41:14] [WARNING] City: Warsaw
[2024-11-07 14:41:14] [WARNING] ISP: PTK CENTERTEL MOBILE data services
```

## Legal Disclaimer

This program is intended strictly for **educational and research purposes**. Please ensure that it is used responsibly and within the bounds of applicable laws and regulations. Misuse of this software is not supported by the creator and is the sole responsibility of the user.

## License

GNU AFFERO GENERAL PUBLIC LICENSE License. See `LICENSE` for more information.

## Author

Created by **im-tesla**.
