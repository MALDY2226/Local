import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import { config } from 'dotenv';
import retry from 'async-retry';

// Initialize dotenv for environment variables
config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = 3000;

const API_KEY = process.env.API_KEY;  // VirusTotal API Key from .env

// Serve static files like HTML, JS, and CSS
app.use(express.static(path.join(__dirname, 'public')));

// Middleware to handle JSON and form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer for handling file uploads
const upload = multer({ dest: 'uploads/' });

// Max file size (32MB) for VirusTotal Free API
const MAX_FILE_SIZE = 32 * 1024 * 1024;

// Function to make API request to VirusTotal for URL scan
async function scanUrlWithVirusTotal(url) {
    return await retry(async bail => {
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/url/report?apikey=${API_KEY}&resource=${url}`);
        if (!response.ok) throw new Error(`Failed to scan URL: ${response.status}`);
        const data = await response.json();
        return data;
    }, { retries: 3 });
}

// Function to make API request to VirusTotal for file scan
async function scanFileWithVirusTotal(filePath) {
    return await retry(async bail => {
        const formData = new FormData();
        formData.append('file', fs.createReadStream(filePath));
        const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/scan?apikey=${API_KEY}`, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) throw new Error(`Failed to scan file: ${response.status}`);
        const data = await response.json();
        return data;
    }, { retries: 3 });
}

// API to handle URL scanning
app.post('/scan-url', async (req, res) => {
    const { url } = req.body;

    if (!url) {
        return res.status(400).json({ error: 'URL is required' });
    }

    try {
        const result = await scanUrlWithVirusTotal(url);
        const combinedResult = (result.positives / result.total) * 100;  // Malware percentage based on API response
        res.json({ combinedResult });
    } catch (error) {
        console.error('Error scanning URL:', error);
        res.status(500).json({ error: 'Error scanning URL' });
    }
});

// API to handle file scanning
app.post('/scan-file', upload.single('file'), async (req, res) => {
    const file = req.file;

    if (!file) {
        return res.status(400).json({ error: 'File is required' });
    }

    // Check if file exceeds the VirusTotal free tier file size limit
    if (file.size > MAX_FILE_SIZE) {
        return res.status(400).json({ error: 'File is too large to scan. Max file size is 32MB.' });
    }

    try {
        const result = await scanFileWithVirusTotal(file.path);
        const combinedResult = (result.positives / result.total) * 100;  // Malware percentage based on API response
        res.json({ combinedResult });
    } catch (error) {
        console.error('Error scanning file:', error);
        res.status(500).json({ error: 'Error scanning file' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
