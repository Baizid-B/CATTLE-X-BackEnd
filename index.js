require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const { OAuth2Client } = require('google-auth-library');

const app = express();

// গুগল ক্লায়েন্ট
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// মিডলওয়্যার
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// CORS কনফিগ
const allowedOrigins = [
    "https://bci-cow.vercel.app",
    "http://localhost:8080",
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:5000"
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

// ক্লাউডিনারি কনফিগ
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// মুলটার কনফিগ
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only images are allowed'));
        }
    }
});

// ক্লাউডিনারি আপলোড ফাংশন
const uploadToCloudinary = (buffer, folder = 'cows') => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { folder: folder, resource_type: 'auto' },
            (error, result) => {
                if (error) reject(error);
                else resolve(result);
            }
        );
        const readableStream = new Readable();
        readableStream.push(buffer);
        readableStream.push(null);
        readableStream.pipe(stream);
    });
};

// টোকেন কুকি সেট ফাংশন
const setTokenCookie = (res, token) => {
    res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/'
    });
};

// MongoDB সংযোগ
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.jhnzp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const VALID_ROLES = ['admin', 'manager', 'user'];
const SALT_ROUNDS = 10;

// গ্লোবাল ভেরিয়েবল
let db;
let usersCollection, cowsCollection, priceIndexCollection, announcementsCollection, testimonialsCollection;

// ডাটাবেস সংযোগ ফাংশন
async function connectDB() {
    if (db) return db;
    try {
        await client.connect();
        db = client.db('bci');
        usersCollection = db.collection('users');
        cowsCollection = db.collection('cows');
        priceIndexCollection = db.collection('price_index');
        announcementsCollection = db.collection('announcements');
        testimonialsCollection = db.collection('testimonials');
        console.log("✅ Connected to MongoDB successfully!");
        return db;
    } catch (error) {
        console.error("❌ MongoDB connection error:", error);
        throw error;
    }
}

// ─── মিডলওয়্যার ফাংশন ───

const verifyToken = (req, res, next) => {
    const token = req.cookies?.token;
    if (!token) {
        return res.status(401).json({ message: "Unauthorized: No session found" });
    }
    try {
        req.user = jwt.verify(token, ACCESS_TOKEN_SECRET);
        next();
    } catch (err) {
        res.status(403).json({ message: "Forbidden: Invalid or expired token" });
    }
};

const verifyAdmin = async (req, res, next) => {
    try {
        await connectDB();
        const user = await usersCollection.findOne({ email: req.user.email });
        if (user?.role !== 'admin') {
            return res.status(403).json({ message: "Forbidden: Admin only" });
        }
        next();
    } catch (err) {
        res.status(500).json({ message: "Server error during admin verification" });
    }
};

const verifyManager = async (req, res, next) => {
    try {
        await connectDB();
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!['admin', 'manager'].includes(user?.role)) {
            return res.status(403).json({ message: "Forbidden: Manager or Admin only" });
        }
        next();
    } catch (err) {
        res.status(500).json({ message: "Server error during manager verification" });
    }
};

// ─── হেলথ চেক ───
app.get('/api/health', async (req, res) => {
    try {
        await connectDB();
        res.json({ 
            status: 'ok', 
            message: 'Server is running',
            timestamp: new Date().toISOString(),
            mongodb: 'connected'
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            message: error.message,
            mongodb: 'disconnected'
        });
    }
});

// ─── AUTH ROUTES ───

app.post('/auth/register', async (req, res) => {
    try {
        await connectDB();
        const { name, email, password } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ message: "নাম, ইমেইল ও পাসওয়ার্ড দিন" });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে" });
        }

        const existing = await usersCollection.findOne({ email });
        if (existing) {
            return res.status(409).json({ message: "এই ইমেইলে আগেই অ্যাকাউন্ট আছে" });
        }

        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
        const newUser = {
            name, 
            email, 
            password: hashedPassword,
            avatar: `https://ui-avatars.com/api/?name=${encodeURIComponent(name)}&background=random`,
            role: "user", 
            provider: "email", 
            created_at: new Date().toISOString(), 
            lastLogin: new Date().toISOString()
        };

        const result = await usersCollection.insertOne(newUser);
        const { password: _, ...safeUser } = { ...newUser, _id: result.insertedId };
        const token = jwt.sign(
            { email: safeUser.email, role: safeUser.role }, 
            ACCESS_TOKEN_SECRET, 
            { expiresIn: '7d' }
        );
        setTokenCookie(res, token);
        res.status(201).json({ user: safeUser });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: "অ্যাকাউন্ট তৈরি ব্যর্থ হয়েছে" });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        await connectDB();
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ message: "ইমেইল ও পাসওয়ার্ড দিন" });
        }

        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "এই ইমেইলে কোনো অ্যাকাউন্ট নেই" });
        }
        if (user.provider === 'google' && !user.password) {
            return res.status(400).json({ message: "এই অ্যাকাউন্টটি Google দিয়ে তৈরি, Google দিয়ে লগইন করুন" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: "পাসওয়ার্ড সঠিক নয়" });
        }

        await usersCollection.updateOne(
            { email }, 
            { $set: { lastLogin: new Date().toISOString() } }
        );
        
        const { password: _, ...safeUser } = user;
        const token = jwt.sign(
            { email: user.email, role: user.role }, 
            ACCESS_TOKEN_SECRET, 
            { expiresIn: '7d' }
        );
        setTokenCookie(res, token);
        res.json({ user: safeUser });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: "লগইন ব্যর্থ হয়েছে" });
    }
});

app.post('/auth/google', async (req, res) => {
    try {
        await connectDB();
        const token = req.body.token || req.body.accessToken || req.body.credential;
        
        if (!token) {
            return res.status(400).json({ message: "No Google token found" });
        }

        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        
        const payload = ticket.getPayload();
        const { name, email, picture } = payload;

        let user = await usersCollection.findOne({ email });

        if (!user) {
            const newUser = {
                name, 
                email, 
                avatar: picture, 
                role: "user", 
                provider: "google",
                created_at: new Date().toISOString(), 
                lastLogin: new Date().toISOString()
            };
            const result = await usersCollection.insertOne(newUser);
            user = { ...newUser, _id: result.insertedId };
        } else {
            await usersCollection.updateOne(
                { email }, 
                { $set: { lastLogin: new Date().toISOString() } }
            );
            user = await usersCollection.findOne({ email });
        }

        const { password: _, ...safeUser } = user;
        const jwtToken = jwt.sign(
            { email: user.email, role: user.role }, 
            ACCESS_TOKEN_SECRET, 
            { expiresIn: '7d' }
        );
        setTokenCookie(res, jwtToken);
        res.json({ user: safeUser });

    } catch (error) {
        console.error("Google Auth Error:", error.message);
        res.status(400).json({ message: "Google verification failed", error: error.message });
    }
});

app.post('/auth/refresh', verifyToken, async (req, res) => {
    try {
        await connectDB();
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const { password: _, ...safeUser } = user;
        res.json({ user: safeUser });
    } catch (err) {
        res.status(403).json({ message: "Invalid or expired token" });
    }
});

app.post('/auth/logout', (req, res) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        path: '/'
    }).json({ success: true });
});

app.get('/auth/me', verifyToken, async (req, res) => {
    try {
        await connectDB();
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const { password: _, ...safeUser } = user;
        res.json({ user: safeUser });
    } catch (err) {
        res.status(500).json({ message: "Server error" });
    }
});

// ─── USER MANAGEMENT ───

app.get('/api/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        await connectDB();
        const users = await usersCollection.find({}, { projection: { password: 0 } }).toArray();
        const formattedUsers = users.map(user => ({
            id: user._id.toString(),
            user_id: user._id.toString(),
            display_name: user.name,
            email: user.email,
            avatar_url: user.avatar,
            created_at: user.created_at,
            roles: [user.role || 'user']
        }));
        res.json(formattedUsers);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch users" });
    }
});

app.post('/api/users/:id/roles', verifyToken, verifyAdmin, async (req, res) => {
    try {
        await connectDB();
        const { id } = req.params;
        const { role } = req.body;
        
        if (!VALID_ROLES.includes(role)) {
            return res.status(400).json({ message: `Invalid role. Must be one of: ${VALID_ROLES.join(', ')}` });
        }
        
        const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) }, 
            { $set: { role } }
        );
        
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "User not found" });
        }
        
        res.json({ success: true, message: `Role updated to: ${role}` });
    } catch (err) {
        res.status(500).json({ message: "Failed to update role" });
    }
});

// ─── COWS ROUTES ───

app.get('/api/cows', async (req, res) => {
    try {
        await connectDB();
        const cows = await cowsCollection.find().toArray();
        res.json(cows);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch cows" });
    }
});

app.get('/api/cows/:id', async (req, res) => {
    try {
        await connectDB();
        const cow = await cowsCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (!cow) {
            return res.status(404).json({ message: "Cow not found" });
        }
        res.json(cow);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch cow" });
    }
});

app.post('/api/cows', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const cowData = { 
            ...req.body, 
            images: req.body.images || [], 
            created_at: new Date().toISOString(), 
            updated_at: new Date().toISOString() 
        };
        const result = await cowsCollection.insertOne(cowData);
        res.status(201).json({ ...cowData, id: result.insertedId.toString(), _id: result.insertedId });
    } catch (err) {
        res.status(500).json({ message: "Failed to add cow" });
    }
});

app.put('/api/cows/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await cowsCollection.updateOne(
            { _id: new ObjectId(req.params.id) }, 
            { $set: { ...req.body, updated_at: new Date().toISOString() } }
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Cow not found" });
        }
        res.json({ success: true, message: "Cow updated successfully" });
    } catch (err) {
        res.status(500).json({ message: "Failed to update cow" });
    }
});

app.delete('/api/cows/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await cowsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Cow not found" });
        }
        res.json({ success: true, message: "Cow deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Failed to delete cow" });
    }
});

app.patch('/api/cows/:id/featured', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await cowsCollection.updateOne(
            { _id: new ObjectId(req.params.id) }, 
            { $set: { featured: req.body.featured } }
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Cow not found" });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Failed to update featured status" });
    }
});

// ─── PRICE INDEX ROUTES ───

app.get('/api/price-index', async (req, res) => {
    try {
        await connectDB();
        const prices = await priceIndexCollection.find().sort({ date: -1 }).toArray();
        res.json(prices);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch price index" });
    }
});

app.post('/api/price-index', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const { price, change_percent, mode } = req.body;
        const newPrice = { 
            price: Number(price), 
            change_percent: Number(change_percent) || 0, 
            mode: mode || 'manual', 
            date: new Date().toISOString() 
        };
        const result = await priceIndexCollection.insertOne(newPrice);
        res.status(201).json({ ...newPrice, _id: result.insertedId });
    } catch (err) {
        res.status(500).json({ message: "Failed to add price" });
    }
});

app.post('/api/smart-price', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const latestPrice = await priceIndexCollection.findOne({}, { sort: { date: -1 } });
        const currentPrice = latestPrice ? latestPrice.price : 250;
        const hour = new Date().getHours();
        const timeBasedChange = hour >= 6 && hour <= 12 ? 5 : (hour >= 18 ? -3 : 0);
        const randomVariation = (Math.random() * 4) - 2;
        const month = new Date().getMonth();
        const eidEffect = (month >= 3 && month <= 5) ? 28 : 0;
        
        const totalChange = timeBasedChange + randomVariation + eidEffect;
        const newPriceValue = Math.round(currentPrice * (1 + totalChange / 100));
        
        const newPrice = {
            price: newPriceValue, 
            change_percent: Math.round(totalChange * 10) / 10,
            mode: 'smart', 
            date: new Date().toISOString(),
            factors: { 
                timeBasedChange, 
                randomVariation: Math.round(randomVariation * 10) / 10, 
                eidEffect 
            }
        };
        await priceIndexCollection.insertOne(newPrice);
        res.json({ 
            newPrice: newPriceValue, 
            changePercent: newPrice.change_percent, 
            factors: newPrice.factors 
        });
    } catch (err) {
        res.status(500).json({ message: "Smart price update failed" });
    }
});

// ─── ANNOUNCEMENTS ROUTES ───

app.get('/api/announcements', async (req, res) => {
    try {
        await connectDB();
        const announcements = await announcementsCollection.find().sort({ created_at: -1 }).toArray();
        res.json(announcements);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch announcements" });
    }
});

app.get('/api/announcements/active', async (req, res) => {
    try {
        await connectDB();
        const now = new Date().toISOString();
        const active = await announcementsCollection.find({
            active: true, 
            $or: [{ end_date: null }, { end_date: { $gte: now } }]
        }).sort({ priority: -1, created_at: -1 }).toArray();
        res.json(active);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch active announcements" });
    }
});

app.post('/api/announcements', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const announcement = { 
            ...req.body, 
            created_at: new Date().toISOString(), 
            updated_at: new Date().toISOString() 
        };
        const result = await announcementsCollection.insertOne(announcement);
        res.status(201).json({ ...announcement, _id: result.insertedId });
    } catch (err) {
        res.status(500).json({ message: "Failed to add announcement" });
    }
});

app.put('/api/announcements/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await announcementsCollection.updateOne(
            { _id: new ObjectId(req.params.id) }, 
            { $set: { ...req.body, updated_at: new Date().toISOString() } }
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Announcement not found" });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Failed to update announcement" });
    }
});

app.delete('/api/announcements/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await announcementsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Announcement not found" });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Failed to delete announcement" });
    }
});

// ─── TESTIMONIALS ROUTES ───

app.get('/api/testimonials', async (req, res) => {
    try {
        await connectDB();
        const testimonials = await testimonialsCollection.find().sort({ created_at: -1 }).toArray();
        res.json(testimonials);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch testimonials" });
    }
});

app.get('/api/testimonials/approved', async (req, res) => {
    try {
        await connectDB();
        const approved = await testimonialsCollection.find({ approved: true }).sort({ created_at: -1 }).toArray();
        res.json(approved);
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch approved testimonials" });
    }
});

app.post('/api/testimonials', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const testimonial = { 
            ...req.body, 
            approved: false, 
            created_at: new Date().toISOString() 
        };
        const result = await testimonialsCollection.insertOne(testimonial);
        res.status(201).json({ ...testimonial, _id: result.insertedId });
    } catch (err) {
        res.status(500).json({ message: "Failed to add testimonial" });
    }
});

app.put('/api/testimonials/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await testimonialsCollection.updateOne(
            { _id: new ObjectId(req.params.id) }, 
            { $set: req.body }
        );
        if (result.matchedCount === 0) {
            return res.status(404).json({ message: "Testimonial not found" });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Failed to update testimonial" });
    }
});

app.delete('/api/testimonials/:id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const result = await testimonialsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "Testimonial not found" });
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ message: "Failed to delete testimonial" });
    }
});

// ─── IMAGE UPLOAD ROUTES ───

app.post('/api/upload', verifyToken, verifyManager, upload.single('image'), async (req, res) => {
    try {
        await connectDB();
        if (!req.file) {
            return res.status(400).json({ message: 'No image file provided' });
        }
        const result = await uploadToCloudinary(req.file.buffer, 'cows');
        res.json({ success: true, url: result.secure_url, public_id: result.public_id });
    } catch (error) {
        res.status(500).json({ message: 'Image upload failed', error: error.message });
    }
});

app.post('/api/upload/multiple', verifyToken, verifyManager, upload.array('images', 10), async (req, res) => {
    try {
        await connectDB();
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ message: 'No image files provided' });
        }
        const uploadPromises = req.files.map(file => uploadToCloudinary(file.buffer, 'cows'));
        const results = await Promise.all(uploadPromises);
        res.json({ 
            success: true, 
            urls: results.map(r => r.secure_url), 
            public_ids: results.map(r => r.public_id) 
        });
    } catch (error) {
        res.status(500).json({ message: 'Image upload failed', error: error.message });
    }
});

app.delete('/api/upload/:public_id', verifyToken, verifyManager, async (req, res) => {
    try {
        await connectDB();
        const { public_id } = req.params;
        await cloudinary.uploader.destroy(public_id);
        res.json({ success: true, message: 'Image deleted successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Image deletion failed' });
    }
});

// ─── ADMIN STATS ───

app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
    try {
        await connectDB();
        const totalUsers = await usersCollection.countDocuments();
        const totalCows = await cowsCollection.countDocuments();
        const featuredCows = await cowsCollection.countDocuments({ featured: true });
        const latestPrice = await priceIndexCollection.findOne({}, { sort: { date: -1 } });
        
        res.json({ 
            totalUsers, 
            totalCows, 
            featuredCows, 
            currentPrice: latestPrice?.price || 0, 
            priceChange: latestPrice?.change_percent || 0 
        });
    } catch (err) {
        res.status(500).json({ message: "Failed to fetch stats" });
    }
});

// ─── ROOT ROUTE ───

app.get('/', (req, res) => {
    res.send('BCI Backend Server is Running with Secure Google Auth Support');
});

// ─── ERROR HANDLING ───

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ─── VERCEL EXPORT ───

module.exports = app;

// ─── LOCAL SERVER ───

if (require.main === module) {
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, async () => {
        console.log(`🚀 Server running on port ${PORT}`);
        try {
            await connectDB();
            console.log('✅ Database connected successfully');
        } catch (error) {
            console.error('❌ Database connection failed:', error);
        }
    });
}