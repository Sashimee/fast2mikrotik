I "forked" the script from this mikrotik blog post : https://forum.mikrotik.com/viewtopic.php?t=111727

This is a script to automatically update Mikrotik Firewall address lists to block suricata/selks flagged traffic through fast.log

##Needed :

https://github.com/BenMenking/routeros-api/blob/master/routeros_api.class.php in the same folder

##Changes :

- Added a second home subnet (TODO : see )
- Added the ability to recognise and handle IPv6 (probably a bit slower if you only use IPv4)

##Notes :

Thank you to tomfisk for making the original script. I implemented this on a SELKS setup and it works just great.

I run it with ```nohup sudo php /usr/local/bin/fast2mikrotik.php &```

##ToDo : 

- Check if by activating the mail function, IPv6 addresses get sent correctly.
