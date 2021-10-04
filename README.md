# Persistence with Scheduled Tasks and website

This small project is a way to keep control over a PC and execute commands on it remotely using a website (like github pages) and sheduled tasks.

Obviously, this is not the most subtle approach, but using encryption and some obfuscation, even for the average tech, the whole thing will be difficult
to detect and remove. The key is to execute turn-off sequence in an order that will not trigger the AV. For example, if the first thing you do as an admin
is to go trash the registry values to turn off WinDefender, you will get flagged. But if you start by disabling AMSI, create a public/pprivate key pair along
with a certificate and approve this certificate on the machine, then you can use executable that uses that certificate without concern. In turn you can 
turn off bigger and bigger features until you have what you need.

Enough talk. Let's quickly explain this.

## Directories and Files

 + schdtask : contains all the scripts that are used as scheduled tasks
 + scripts  : scripts that are executed once (like install, or other commands)
 + dat      : contains data files. Passwords, email addresses, etc...