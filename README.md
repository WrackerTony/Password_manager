# 🔐 Secure Password Manager

<div align="center">
  
  ![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
  ![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
  ![Security](https://img.shields.io/badge/Security-Critical-red?style=for-the-badge)
  

  <br>
  
  ### 🛡️ **A Professional-Grade Password Manager Built with Security in Mind** 🛡️
  
  *Secure • Fast • Reliable • User-Friendly*
  
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=20&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=Secure+Password+Storage;Advanced+Encryption+Technology;User-Friendly+Interface;Cross-Platform+Compatibility" alt="Typing SVG" />
  
</div>

<table>
<tr>

<td width="50%">

### 💻 **User Experience**
- 🎨 **Modern Tkinter GUI**
- 👤 **Multi-user support**


</tr>
</table>

---

## 🚀 **Quick Start**


### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/WrackerTony/Password_manager.git
   cd password_manager
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

---

## 📋 **System Requirements**

<div align="center">

| Component | Requirement |
|-----------|-------------|
| **Python** | 3.7+ |

</div>


## 📁 **Project Structure**

```
password_manager/
├── 📄 main.py              # Main application entry point
├── 🗄️ database.py          # Database operations & management
├── 🔐 encryption.py        # Encryption/decryption utilities
├── 📋 requirements.txt     # Python dependencies
└── 📖 README.md           # Project documentation
```

---

## 🔧 **Core Components**

### 🔐 **Encryption Module** (`encryption.py`)
- **PBKDF2** key derivation with SHA-256
- **Fernet** symmetric encryption
- **Salt generation** for enhanced security
- **bcrypt** password hashing

### 🗄️ **Database Module** (`database.py`)
- **SQLite** integration
- **User management** system
- **Password storage** with encryption
- **CRUD operations** for password entries

### 💻 **Main Application** (`main.py`)
- **Tkinter GUI** implementation
- **User authentication** flow
- **Password management** interface
- **Security validation**

---

## 🛡️ **Security Features**

<div align="center">

| Feature | Implementation | Security Level |
|---------|----------------|----------------|
| **Master Password** | bcrypt hashing | 🔴 **Critical** |
| **Data Encryption** | AES-256 (Fernet) | 🔴 **Critical** |
| **Key Derivation** | PBKDF2 (100k iterations) | 🟠 **High** |
| **Salt Generation** | Cryptographically secure | 🟠 **High** |
| **Database Security** | Encrypted password storage | 🟡 **Medium** |

</div>


## 👨‍💻 **Author**

<div align="center">
  
  **WrackerTony**
  
  [![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/WrackerTony)
  
</div>

<div align="center">
  
  ### 🌟 **If you found this project helpful, please give it a star!** ⭐
  
  <img src="https://forthebadge.com/images/badges/built-with-love.svg" alt="Built with Love">
  <img src="https://forthebadge.com/images/badges/made-with-python.svg" alt="Made with Python">
  
  ---
  
  **© 2025 Secure Password Manager. All rights reserved.**
  
</div>
