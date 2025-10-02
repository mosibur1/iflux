
---

<h1 align="center">Iflux Bot</h1>

<p align="center">
<strong>Boost your productivity with Iflux Bot – your friendly automation tool that handles key tasks with ease!</strong>
</p>

<p align="center" style="display: flex; justify-content: center; gap: 8px; flex-wrap: wrap;">
  <a href="https://codeberg.org/livexords/ddai-bot/actions" style="display: inline-block;">
    <img src="https://img.shields.io/badge/build-passed-brightgreen" alt="Build Status" />
  </a>
  <a href="https://t.me/livexordsscript" style="display: inline-block;">
    <img src="https://img.shields.io/badge/Telegram-Join%20Group-2CA5E0?logo=telegram&style=flat" alt="Telegram Group" />
  </a>
</p>

---

## 🚀 About the Bot

Iflux Bot is your automation buddy designed to simplify daily operations. This bot takes over repetitive tasks so you can focus on what really matters. With Iflux Bot, you get:

- **Auto Mining Point ⛏️:**
  Automatically handles mining points with smart node management — no more manual activation or node checks required.
- **Multi Account Support 👥:**  
  Manage multiple accounts effortlessly with built-in multi account support.
- **Thread System 🧵:**  
  Run tasks concurrently with configurable threading options to improve overall performance and speed.
- **Configurable Delays ⏱️:**  
  Fine-tune delays between account switches and loop iterations to match your specific workflow needs.
- **Support Proxy 🔌:**
  Use HTTP/HTTPS proxies to enhance your multi-account setups. The bot automatically picks a random proxy from your list for each session to improve reliability and anonymity.
- **Random User-Agent 🎭:**
  Each session gets a random User-Agent to mimic real browsers and make your automation harder to detect. Works seamlessly with or without proxies.
- **Auto Tuner 🤖** _(hidden from config)_
  Automatically adjusts queue size, poll interval, and deduplication depending on your device CPU, memory, and network speed.
- **Resource Friendly 🧠** _(hidden from config)_
  Smart memory cleanup and lightweight network handling to keep the bot stable on low-spec VPS/PC.
- **Safe Networking 🚦** _(hidden from config)_
  Built-in retry, backoff, and proxy testing system to ensure requests stay reliable even if proxies fail.
- **Plug & Play ⚡**
  Just prepare your accounts, adjust the config.json, and run. No complicated setup required.

Iflux Bot is built with flexibility and efficiency in mind – it's here to help you automate your operations and boost your productivity!

---

## 🌟 Version Updates

**Current Version: v1.0.0**

### v1.0.0 - Latest Update

**Added Features:**

- Auto mining point
- Multi-Account Support
- Thread System
- Configurable Delays
- Proxy Support
- Random User-Agent
- Auto Tuner _(automatic)_
- Resource Friendly _(automatic)_
- Safe Networking _(automatic)_

---

## 📝 Register

Before you start using Iflux-bot Bot, make sure to register your account.  
Click the link below to get started:

[🔗 Register for Iflux Bot](https://depin.iflux.global?ref=MjUxMDAxMzAx)

---

## ⚙️ Configuration

### Main Bot Configuration (`config.json`)

```json
{
  "mining": true,
  "node_per_account": 50,
  "thread": 1,
  "proxy": false,
  "delay_account_switch": 10,
  "delay_loop": 86400
}
```

| **Setting**            | **Description**                               | **Default Value** |
| ---------------------- | --------------------------------------------- | ----------------- |
| `mining`               | Enable/disable mining process                 | `true`            |
| `node_per_account`     | Maximum number of nodes per account           | `50`              |
| `thread`               | Number of threads to run concurrently         | `1`               |
| `proxy`                | Enable proxy usage for multi-account setups   | `false`           |
| `delay_account_switch` | Delay (in seconds) between switching accounts | `10`              |
| `delay_loop`           | Delay (in seconds) before the next loop       | `86400`           |

---

## 📅 Requirements

- **Minimum Python Version:** `Python 3.9+`
- **Required Libraries:**
  - requests
  - urllib3
  - colorama
  - fake-useragent
  - brotli
  - chardet
  - psutil

These are installed automatically when running:

```bash
pip install -r requirements.txt
```

---

## 📅 Installation Steps

### Main Bot Installation

1. **Clone the Repository**

   ```bash
   git clone https://codeberg.org/LIVEXORDS/iflux-bot.git
   ```

2. **Navigate to the Project Folder**

   ```bash
   cd iflux-bot
   ```

3. **Install Dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Your Query**

   Create a file named `query.txt` and add your data.

   **Example:**

   ```
   email|password
   yes|123132
   ```

5. **Set Up Proxy (Optional)**  
   To use a proxy, create a `proxy.txt` file and add proxies in the format:

   ```
   http://username:password@ip:port
   ```

   _Only HTTP and HTTPS proxies are supported._

6. **Run Bot**

   ```bash
   python main.py
   ```

---

### 🔹 Need Free Proxies for Farming or Testnets?

Get **1GB/month free proxies** from [Webshare.io](https://www.webshare.io/?referral_code=k8udyiwp88n0) — no credit card, no KYC.
Perfect for bots, farming, automation, and multi-account setups.

> _We personally use this for development and multi-account setups – reliable and simple._

---

## 📂 Project Structure

```
iflux-bot/
├── config.json         # Main configuration file
├── extension.txt       # Stores extension/account data (per account nodes)
├── proxy.txt           # (Optional) File containing proxy data
├── query.txt           # File to input your query data
├── main.py             # Main entry point to run the bot
├── requirements.txt    # Python dependencies
├── LICENSE             # License for the project
└── README.md           # Project documentation
```

---

## 🛠️ Contributing

This project is developed by **Livexords**.  
If you have ideas, questions, or want to contribute, please join our Telegram group for discussions and updates.  
For contribution guidelines, please consider:

- **Code Style:** Follow standard Python coding conventions.
- **Pull Requests:** Test your changes before submitting a PR.
- **Feature Requests & Bugs:** Report and discuss via our Telegram group.

<div align="center">
  <a href="https://t.me/livexordsscript" target="_blank">
    <img src="https://img.shields.io/badge/Join-Telegram%20Group-2CA5E0?logo=telegram&style=for-the-badge" height="25" alt="Telegram Group" />
  </a>
</div>

---

## 📖 License

This project is licensed under the **MIT License**.  
See the [LICENSE](LICENSE) file for more details.

---

## 🔍 Usage Example

After installation and configuration, simply run:

```bash
python main.py
```

You should see output indicating the bot has started its operations. For further instructions or troubleshooting, please check our Telegram group or open an issue in the repository.

---

## 📣 Community & Support

For support, updates, and feature requests, join our Telegram group.  
This is the central hub for all discussions related to Iflux-bot Bot, including roadmap ideas and bug fixes.

---
