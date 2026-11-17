# Project Skynet Serverside Backend 

## Description
Server-side backend for Project Skynet. Handles connecting user to frontend dashboard.

## Installation
First, Node.js and npm should be installed on the machine running the server. Their presence can be verified with the following commands
```bash
node -v
npm -v
```
After node is installed, the following command should automatically install all necessary dependencies for the backend to function
```bash
npm install
```
If this doesn't work, dependencies can be installed manually with the following commands
```bash
npm install express
```

## Usage
On start server needs to identify output dump for the agent. Defaults to checking filepath `./fixtures`. If the disired filepath is different, it can be given as an argument to overwrite the default setting.

Afteer installation, server can be started with any one of the following ways.
```bash
npm start

npm start <path>

node server.js

node server.js <path>
```

Server can also be started in Testing mode, allowing it to automatically restart when changes are saved to server.js. This can be done with any one of the following commands
```bash
npm text

npm test <path>

npx nodemon server.js

npx nodemon server.js <path>
```

Once server is running, for testing purposes it can be connected to on a local machine by going to any browser at localhost:`PORT`. By default `PORT` is set to 8080. The terminal the server is launched from should log the port numebr on staartup in case it has been changed.