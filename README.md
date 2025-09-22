# CSCE-3550---Project1
Project 1 files are included above

Please note that AI was used to develop the JWKS server. This was my first exposure to JSON Web Key Sets and JSON
web tokens, so I relied heavily on AI (chatGPT to be specific) to help me formulate my thoughts about how the
server was meant to function according to the assignment requirements. First I had to specify that the language I wanted to use was python. And after that I specified that I wanted the following features in the JWKS server:


1) Key generation in RSA pairs with an associate KeyID and expiry timestamps
2) Web server that serves HTTP on port 8080 that had a RESTful JWKS endpoint serving public keys in
   JWKS format (where only valid keys were served), and an /autH endpoint that returned unexpired sined JWT on
   a POST request.


At first, ChatGPT returned python code that built the requests with a psql connection, but I shot down
that attempt down by mentioning that I wanted a pure python program to fulfill the requirements.
I then took the generated code and adjusted it to take requests constantly until the server was stopped by
hitting the enter key. I took the time to then understand the code that was generated and look through it
line-by-line to ensure that It matched the requirements of the JWKS server as desired in project 1.
As I took the time to understand why certain lines of code were generated, I then commented the lines
I felt needed explaination so that I could build up the server later on easir. Afterward, I ran the
gradebot program on the python code and got the score depicted in the .png file. 

