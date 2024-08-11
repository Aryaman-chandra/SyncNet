const express  = require("express");
const fs = require('fs');
const path = require('path');
const app = express();
const port = 5000;

// Define the path to the JSON file
const jsonFilePath = path.join(__dirname, '..', 'groups.json');
const pendingRequestFilePath = path.join(__dirname, '..', 'pending_requests.json');

// Middleware to parse JSON bodies
app.use(express.json());

app.get('/organization_groups', (req, res) => {
    fs.readFile(jsonFilePath, 'utf8', (err, data) => {
        if (err) {
            res.status(500).json({ error: 'Error reading the JSON file' });
            return;
        }
        try {
            const jsonData = JSON.parse(data);
            res.json(jsonData);
        } catch (parseError) {
            res.status(500).json({ error: 'Error parsing the JSON data' });
        }
    });
});

// POST endpoint to add a user to the pending requests
app.post('/submit_request', (req, res) => {
    const { group_name, ipAddress } = req.body;

    // Validate input
    if (!group_name || !ipAddress) {
        return res.status(400).json({ error: 'Group name and IP Address are required' });
    }

    // Get the current date and time
    const now = new Date();
    const date = now.toLocaleDateString(); // Format: MM/DD/YYYY
    const time = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }); // Format: HH:MM:SS AM/PM

    // Read existing data
    fs.readFile(pendingRequestFilePath, 'utf8', (err, data) => {
        if (err && err.code !== 'ENOENT') {
            return res.status(500).json({ error: 'Error reading the pending requests file' });
        }

        let pendingRequests = [];
        if (data) {
            try {
                pendingRequests = JSON.parse(data);
            } catch (parseError) {
                return res.status(500).json({ error: 'Error parsing the pending requests data' });
            }
        }

        // Add the new request with date and time
        pendingRequests.push({ group_name, ipAddress, date, time });

        // Write the updated data
        fs.writeFile(pendingRequestFilePath, JSON.stringify(pendingRequests, null, 2), 'utf8', (writeErr) => {
            if (writeErr) {
                return res.status(500).json({ error: 'Error writing to the pending requests file' });
            }
            res.status(201).json({ message: 'Pending request added successfully' });
        });
    });
});


app.listen(port,()=>{
    console.log(`Server is running on ${port}`)
});