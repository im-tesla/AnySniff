# AnySniff

**AnySniff** is a C++20 program designed for educational and research purposes to identify the IP addresses of someone by them calling us or by calling them via AnyDesk. This tool logs information such as IP address, country, city, and ISP, allowing users to gain insights into session details during AnyDesk sessions.

## Features

- **IP Sniffing:** Detects the victim IP address of by making call or receiving call from them through AnyDesk.
- **Geolocation Information:** Logs country, city, and ISP details based on IP addresses.
- **Efficient Logging:** Ensures that each IP is logged only once to avoid redundant data.

## Installation

1. Clone the repository:
   `git clone https://github.com/im-tesla/AnySniff.git`
2. Open the project in **Visual Studio 2022**.
3. Ensure that the project is set to **C++20** standard in project properties.
4. Build the solution using Visual Studio's built-in compiler.

## Usage

Run the compiled executable from the output directory:
```
.\AnySniff.exe
```
The program will initialize and begin sniffing for someone IP, logging them along with relevant geolocation data.

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
