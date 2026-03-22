const express = require('express');
const path = require('path');
const fs = require('fs').promises;
const multer = require('multer');
const ActiveDirectory = require('activedirectory2');
const app = express();
//const port = 3000;

// ===== EMBEDDED LDAP CONFIGURATION =====
const LDAP_CONFIG = {
    url: process.env.LDAP_URL,
    baseDN: process.env.LDAP_BASE_DN,
    username: process.env.LDAP_USERNAME,
    password: process.env.LDAP_PASSWORD,
    
};

const port = process.env.PORT;

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: 'uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, `script-${uniqueSuffix}.ps1`);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (path.extname(file.originalname).toLowerCase() === '.ps1') {
            cb(null, true);
        } else {
            cb(new Error('Only PowerShell script (.ps1) files are allowed'));
        }
    }
});

// Ensure directories exist
const ensureDirectories = async () => {
    try {
        await fs.mkdir('uploads', { recursive: true });
        await fs.mkdir('scripts', { recursive: true });
    } catch (error) {
        console.error('Error creating directories:', error);
    }
};
ensureDirectories();

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// Store uploaded scripts info
const uploadedScripts = new Map();

// Input validation middleware
const validateScriptArgs = (req, res, next) => {
    const { scriptArgs } = req.body;
    
    if (scriptArgs && !/^[a-zA-Z0-9\s\-_=,."\\:]+$/.test(scriptArgs)) {
        return res.status(400).json({ error: 'Invalid characters in script arguments' });
    }
    
    if (scriptArgs && scriptArgs.length > 500) {
        return res.status(400).json({ error: 'Script arguments too long' });
    }
    
    next();
};

// === LDAP AD SEARCH ENDPOINTS ===

// Search AD group members with recursive option
app.post('/api/ad/search-group-recursive', async (req, res) => {
    const { 
        groupName,
        attributes = 'displayName,mail,sn,title,telephoneNumber,pager,sAMAccountName',
        page = 1,
        pageSize = 200
    } = req.body;

    console.log('=== Group Search Request (Recursive) ===');
    console.log('GroupName:', groupName);
    console.log('Attributes:', attributes);
    console.log('Page:', page);
    console.log('PageSize:', pageSize);
    console.log('=========================================');

    if (!groupName) {
        return res.status(400).json({ 
            success: false, 
            error: 'Group name is required' 
        });
    }

    try {
        const config = {
            url: LDAP_CONFIG.url,
            baseDN: LDAP_CONFIG.baseDN,
            username: LDAP_CONFIG.username,
            password: LDAP_CONFIG.password
        };

        const ad = new ActiveDirectory(config);

        ad.findGroup(groupName, (err, group) => {
            if (res.headersSent) return;
            
            if (err || !group) {
                return res.json({ 
                    success: false, 
                    error: 'Group not found' 
                });
            }

            const groupDN = group.dn;
            
            // Use recursive filter to find all members including nested groups
            const recursiveFilter = `(memberOf:1.2.840.113556.1.4.1941:=${groupDN})`;
            
            console.log(`Using recursive filter: ${recursiveFilter}`);

            const attrList = attributes.split(',').map(a => a.trim());
            
            const allAttributes = [
                'dn', 'cn', 'name','sAMAccountName', 'sn', 'userPrincipalName',
                'userAccountControl', 'displayName', 'mail', 
                'title', 'telephoneNumber', 'pager',
                'TelephoneNumber', 'PhoneNumber', 'homePhone', 'mobile',
                'Pager', 'PagerNumber', 'SN',
                ...attrList
            ];

            const searchOptions = {
                filter: recursiveFilter,
                attributes: [...new Set(allAttributes)],
                scope: 'sub',
                paged: {
                    pageSize: 1000
                }
            };

            ad.findUsers(searchOptions, (err, users) => {
                if (res.headersSent) return;
                
                if (err) {
                    console.error('Error in recursive search:', err);
                    return res.json({ 
                        success: false, 
                        error: 'Search failed: ' + err.message 
                    });
                }

                if (!users || users.length === 0) {
                    return res.json({
                        success: true,
                        groupName: groupName,
                        groupInfo: {
                            dn: group.dn,
                            cn: group.cn
                        },
                        totalUsers: 0,
                        users: [],
                        currentPage: page,
                        pageSize: pageSize,
                        totalPages: 0,
                        message: 'No users found in this group'
                    });
                }

                console.log(`✅ Found ${users.length} users recursively`);

                const processedUsers = users.map(user => {
                    const userData = {
                        sAMAccountName: user.sAMAccountName || user.SAMAccountName || extractSAMFromDN(user.dn) || null,
                        name: user.name || user.cn,
                        dn: user.dn,
                        sn: user.sn || user.SN || extractSnFromName(user.name) || null,
                        userPrincipalName: user.userPrincipalName,
                        displayName: user.displayName || user.DisplayName || null,
                        mail: user.mail || user.Mail || user.email || null,
                        title: user.title || user.Title || null,
                        
                        telephoneNumber: user.telephoneNumber || 
                                       user.TelephoneNumber || 
                                       user.phoneNumber || 
                                       user.PhoneNumber || 
                                       null,
                        
                        pager: user.pager || 
                              user.Pager || 
                              user.pagerNumber || 
                              user.PagerNumber || 
                              null
                    };

                    if (user.userAccountControl !== undefined) {
                        userData.enabled = (user.userAccountControl & 2) !== 2;
                    } else {
                        userData.enabled = true;
                    }

                    return userData;
                });

                // Remove duplicates based on DN
                const uniqueUsers = [];
                const seenDNs = new Set();
                
                processedUsers.forEach(user => {
                    if (!seenDNs.has(user.dn)) {
                        seenDNs.add(user.dn);
                        uniqueUsers.push(user);
                    }
                });

                console.log(`After deduplication: ${uniqueUsers.length} unique users`);

                // Calculate pagination
                const totalUsers = uniqueUsers.length;
                const totalPages = Math.ceil(totalUsers / pageSize);
                const currentPage = Math.min(page, totalPages) || 1;
                const startIndex = (currentPage - 1) * pageSize;
                const endIndex = Math.min(startIndex + pageSize, totalUsers);
                const paginatedUsers = uniqueUsers.slice(startIndex, endIndex);

                // Count statistics
                const withTelephone = uniqueUsers.filter(u => u.telephoneNumber).length;
                const withPager = uniqueUsers.filter(u => u.pager).length;

                res.json({
                    success: true,
                    domain: extractDomain(LDAP_CONFIG.url),
                    groupName: groupName,
                    groupInfo: {
                        dn: group.dn,
                        cn: group.cn
                    },
                    totalUsers: totalUsers,
                    users: paginatedUsers,
                    currentPage: currentPage,
                    pageSize: pageSize,
                    totalPages: totalPages,
                    startIndex: startIndex + 1,
                    endIndex: endIndex,
                    attributes: ['sAMAccountName','name', 'sn', 'displayName', 'mail', 'title', 'telephoneNumber', 'pager', 'enabled'],
                    recursive: true,
                    stats: {
                        withTelephone: withTelephone,
                        withPager: withPager,
                        duplicateCount: processedUsers.length - uniqueUsers.length
                    }
                });
            });
        });

    } catch (error) {
        console.error('Recursive search error:', error);
        if (!res.headersSent) {
            res.status(500).json({ 
                success: false, 
                error: error.message 
            });
        }
    }
});

// Export ALL group members to CSV
app.post('/api/ad/export-group-csv', async (req, res) => {
    const { 
        groupName,
        attributes = 'displayName,mail,sn,title,telephoneNumber,pager,sAMAccountName'
    } = req.body;

    console.log('=== CSV Export Request ===');
    console.log('GroupName:', groupName);

    if (!groupName) {
        return res.status(400).json({ 
            success: false, 
            error: 'Group name is required' 
        });
    }

    try {
        const config = {
            url: LDAP_CONFIG.url,
            baseDN: LDAP_CONFIG.baseDN,
            username: LDAP_CONFIG.username,
            password: LDAP_CONFIG.password
        };

        const ad = new ActiveDirectory(config);

        ad.findGroup(groupName, (err, group) => {
            if (err || !group) {
                return res.status(404).json({ 
                    success: false, 
                    error: 'Group not found' 
                });
            }

            const groupDN = group.dn;
            const recursiveFilter = `(memberOf:1.2.840.113556.1.4.1941:=${groupDN})`;
            
            const attrList = attributes.split(',').map(a => a.trim());
            
            const allAttributes = [
                'dn', 'cn', 'name','sAMAccountName', 'sn', 'userPrincipalName',
                'userAccountControl', 'displayName', 'mail', 
                'title', 'telephoneNumber', 'pager',
                ...attrList
            ];

            const searchOptions = {
                filter: recursiveFilter,
                attributes: [...new Set(allAttributes)],
                scope: 'sub',
                paged: {
                    pageSize: 5000
                }
            };

            ad.findUsers(searchOptions, (err, users) => {
                if (err) {
                    return res.status(500).json({ 
                        success: false, 
                        error: 'Search failed: ' + err.message 
                    });
                }

                if (!users || users.length === 0) {
                    return res.status(404).json({ 
                        success: false, 
                        error: 'No users found' 
                    });
                }

                // Process users and remove duplicates
                const processedUsers = [];
                const seenDNs = new Set();
                
                users.forEach(user => {
                    if (!seenDNs.has(user.dn)) {
                        seenDNs.add(user.dn);
                        
                        processedUsers.push({
                            sAMAccountName: user.sAMAccountName || '',
                            name: user.name || user.cn,
                            sn: user.sn || user.SN || '',
                            displayName: user.displayName || '',
                            mail: user.mail || '',
                            title: user.title || '',
                            telephoneNumber: user.telephoneNumber || '',
                            pager: user.pager || '',
                            enabled: user.userAccountControl ? (user.userAccountControl & 2) !== 2 : true
                        });
                    }
                });

                // Generate CSV
                const headers = ['Username', 'Name', 'Surname', 'Display Name', 'Email', 'Title', 'Telephone', 'Pager', 'Status'];
                const csvRows = [headers.join(',')];

                processedUsers.forEach(user => {
                    const row = [
                        user.sAMAccountName,
                        user.name,
                        user.sn,
                        user.displayName,
                        user.mail,
                        user.title,
                        user.telephoneNumber,
                        user.pager,
                        user.enabled ? 'Enabled' : 'Disabled'
                    ];
                    
                    const escapedRow = row.map(field => {
                        if (typeof field === 'string' && (field.includes(',') || field.includes('"') || field.includes('\n'))) {
                            return `"${field.replace(/"/g, '""')}"`;
                        }
                        return field;
                    });
                    
                    csvRows.push(escapedRow.join(','));
                });

                const csvContent = csvRows.join('\n');
                
                res.setHeader('Content-Type', 'text/csv;charset=utf-8');
                res.setHeader('Content-Disposition', `attachment; filename="${groupName.replace(/[^a-z0-9]/gi, '_')}_members.csv"`);
                res.send(csvContent);
            });
        });

    } catch (error) {
        console.error('Export error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Helper function to extract domain from LDAP URL
function extractDomain(ldapUrl) {
    try {
        const match = ldapUrl.match(/ldaps?:\/\/([^:\/]+)/);
        if (match) {
            return match[1];
        }
    } catch (e) {}
    return 'Unknown Domain';
}

// Helper function to extract name from DN
function extractNameFromDN(dn) {
    if (!dn) return 'Unknown';
    try {
        const match = dn.match(/CN=([^,]+)/i);
        return match ? match[1] : dn;
    } catch (e) {
        return dn;
    }
}

// Helper function to extract sAMAccountName from DN
function extractSAMFromDN(dn) {
    if (!dn) return 'unknown';
    try {
        const match = dn.match(/CN=([^,]+)/i);
        if (match) {
            return match[1].toLowerCase().replace(/\s+/g, '.');
        }
        return 'unknown';
    } catch (e) {
        return 'unknown';
    }
}

// Helper function to extract surname from name
function extractSnFromName(name) {
    if (!name) return null;
    const parts = name.split(' ');
    return parts.length > 1 ? parts[parts.length - 1] : name;
}

// === SCRIPT UPLOAD ENDPOINTS ===

app.post('/upload-script', upload.single('script'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No script file uploaded' });
        }

        const scriptId = Date.now().toString();
        const scriptPath = req.file.path;
        const originalName = req.file.originalname;

        uploadedScripts.set(scriptId, {
            path: scriptPath,
            originalName: originalName,
            uploadedAt: new Date()
        });

        const content = await fs.readFile(scriptPath, 'utf8');
        const preview = content.split('\n').slice(0, 10).join('\n');

        res.json({
            success: true,
            scriptId: scriptId,
            filename: originalName,
            preview: preview,
            message: 'Script uploaded successfully'
        });

    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload script' });
    }
});

app.get('/scripts', (req, res) => {
    const scripts = Array.from(uploadedScripts.entries()).map(([id, info]) => ({
        id: id,
        filename: info.originalName,
        uploadedAt: info.uploadedAt
    }));
    res.json(scripts);
});

app.delete('/script/:id', async (req, res) => {
    const scriptId = req.params.id;
    const scriptInfo = uploadedScripts.get(scriptId);

    if (!scriptInfo) {
        return res.status(404).json({ error: 'Script not found' });
    }

    try {
        await fs.unlink(scriptInfo.path);
        uploadedScripts.delete(scriptId);
        res.json({ success: true, message: 'Script deleted' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ error: 'Failed to delete script' });
    }
});

app.post('/run-script', validateScriptArgs, async (req, res) => {
    const { scriptArgs = '', scriptId } = req.body;

    let scriptPath;
    
    if (scriptId && uploadedScripts.has(scriptId)) {
        const scriptInfo = uploadedScripts.get(scriptId);
        scriptPath = scriptInfo.path;
    } else {
        scriptPath = path.join(__dirname, 'scripts', 'sample-ad-query.ps1');
    }

    try {
        await fs.access(scriptPath);
    } catch {
        return res.status(404).json({ 
            success: false, 
            error: 'Script not found. Please upload a script first.' 
        });
    }

    const args = scriptArgs ? scriptArgs.split(' ') : [];
    const ps = require('child_process').spawn('powershell.exe', [
        '-ExecutionPolicy', 'Bypass',
        '-File', scriptPath,
        ...args
    ]);

    let stdout = '';
    let stderr = '';

    ps.stdout.on('data', (data) => {
        stdout += data.toString();
    });

    ps.stderr.on('data', (data) => {
        stderr += data.toString();
    });

    ps.on('close', (code) => {
        if (code !== 0) {
            return res.json({ 
                success: false,
                error: stderr || `Process exited with code ${code}`,
                output: stdout
            });
        }
        
        res.json({ 
            success: true,
            output: stdout
        });
    });
});

// Cleanup old uploaded files (every hour)
setInterval(async () => {
    const oneHourAgo = Date.now() - (60 * 60 * 1000);
    for (const [id, info] of uploadedScripts.entries()) {
        if (info.uploadedAt < oneHourAgo) {
            try {
                await fs.unlink(info.path);
                uploadedScripts.delete(id);
                console.log(`Cleaned up old script: ${info.originalName}`);
            } catch (error) {
                console.error('Cleanup error:', error);
            }
        }
    }
}, 60 * 60 * 1000);

app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
    console.log('\n🔒 LDAP Configuration:');
    console.log(`   URL: ${LDAP_CONFIG.url}`);
    console.log(`   BaseDN: ${LDAP_CONFIG.baseDN}`);
    console.log(`   Service Account: ${LDAP_CONFIG.username}`);
});