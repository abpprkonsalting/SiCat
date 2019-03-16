# SiCat

General system description
=======================

The captive portal system SiCat with social network authentication is a system designed to 
provide conditional access to networks (Internet) to users through WIFI networks in public places. 
The conditionality of this access is determined by the user loging in a social network 
(currently implemented variant is facebook) and posting a predefined message of a sponsor.

The system is composed by a firmware update that needs to be flashed in a capable router 
(successfully tested with RB951Ui-2HnD with OS OpenWRT), and a central server that functions 
as authentication server and central control point for all clients / devices.

SiCat firmware description
=======================

Captive portal firmware for client's authentication using social networks (www.facebook.com) 
based in NoCatSplash. Tested to work with Mikrotik wifi router RB951Ui-2HnD with OS OpenWRT.

This project is the firmware update to the router, and in its current stage it just provide service 
based in two periods of times, one short in which the client is redirected to the central server so 
he could fullfill the condition, and one longer in which the client has given access to the whole 
service; when this last time period is completed the client must fullfill the condition again.

During the development of the project was tested an approach for limiting the access of the client to 
resources based in a mecanism for determining url locations dynamically, but it's use was posponed for 
later versions after some issues with DNS caches used by browsers could be solved.

Support for https traffic capture and redirection (as conflicting as this could be for user experience) 
is still under development.

The project was stop at the begining of 2015. 



