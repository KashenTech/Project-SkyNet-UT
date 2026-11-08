/**
 * @auth Jacob Bitter   (jbitter4@rockets.utoledo.edu)
 */


/**
 * Global variables to hold data.
 */
let hosts;
let events = [];

/**
 * @const express   Imports the Express package to simplyfy the work
 * @const fs        Imports necessary framework for file manipulation
 * @const fsp       Imports more necessary framework for file manipulation
 * @const path      Imports necessary framework for filepath manipulation
 */
const express = require('express');
const fs = require("node:fs");
const fsp = require("node:fs/promises")
const { createInterface } = require("node:readline/promises"); 
const path = require("node:path");

/**
 * @const app           New express instance
 * @const PORT          the port on local device for the app to listen on
 */
const app = express();
const PORT = 8080;

/**
 * Gives the app access to the folder ./public, where all of the frontend pages are held.
 * 
 * Also enables express's built-in JSON package
 */
app.use(express.static('public'));
app.use(express.json());


/**
 * Function to read data files.
 * 
 * @argument inPath     Absolute Path to the directory that Agent will dump json data in.
 */
async function processData(inPath) {
    //read hosts.json
    const hostsFilepath = path.join(inPath, "/host.json")
    const hostsJsonData = await fsp.readFile(hostsFilepath) 
    hosts = JSON.parse(hostsJsonData);


    //creaate readstream for events.jsonl 
    const eventsFilepath = path.join(inPath, "/events.jsonl")
    const rl = createInterface({
        input: fs.createReadStream(eventsFilepath),
        crlfDelay: Infinity,
    });
    
    //read events.jsonl
    for await (const line of rl){
        const trimmed = line.trim();
        if(trimmed){
            events.push(JSON.parse(trimmed));
        }
    }
}

/**
 * Sends index.html when a user connects for the first time
 */
app.get("/", (req, res) => {
    res.send('index.html');
});

/**
 * Sends json message containing  info;rmation to be displayed to user.
 */
app.get("/initialConnect", (req, res) => {
    console.log("New user connected");

    let responseData = {
            message:"sending test data",
            body:{
                hosts: [hosts],
                events: [events]
        }
    };

    res.send(responseData);
});

/**
 * Open app on PORT, log in console that server is started.
 * Start parsing JSON Data at given location.
 */
app.listen(PORT, ()=> console.log('Server started. Listening on PORT: ' + PORT + ". \n Arg given: " + process.argv[2]));

/**
 * @const dataPath  The absolute path to directory user indicates agent will dump JSON Data. If arg is present, uses that.
 *                  Otherwise, resorts to default path (./skynet_output).
 */
const dataPath = ((process.argv.length > 2) ? process.argv[2] : path.join(__dirname, "/skynet_output"));

/**
 * Function to begin parsing data.
 */
processData(dataPath);