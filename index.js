require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { Readable } = require('stream');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:8080', 'http://localhost:5173', 'http://localhost:3000',"https://bci-cow.vercel.app"],
    credentials: true
}));

const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.jhnzp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET || 'secret_key_12345';
const VALID_ROLES = ['admin', 'manager', 'user'];
const SALT_ROUNDS = 10;

// ─────────────────────────────────────────────────────────────────────
//  CLOUDINARY CONFIGURATION
// ─────────────────────────────────────────────────────────────────────
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer setup (memory storage for buffer)
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only images are allowed'));
        }
    }
});

// Helper function to upload buffer to cloudinary
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

// Cookie helper
const setTokenCookie = (res, token) => {
    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000
    });
};

async function run() {
    try {
        const db = client.db('bci');
        const usersCollection = db.collection('users');
        const cowsCollection = db.collection('cows');
        const priceIndexCollection = db.collection('price_index');
        const announcementsCollection = db.collection('announcements');
        const testimonialsCollection = db.collection('testimonials');

        console.log("Connected to MongoDB successfully!");

        // ─────────────────────────────────────────────────────────────────────
        //  MIDDLEWARES
        // ─────────────────────────────────────────────────────────────────────

        const verifyToken = (req, res, next) => {
            const token = req.cookies?.token;
            if (!token) return res.status(401).json({ message: "Unauthorized: No session found" });
            try {
                req.user = jwt.verify(token, ACCESS_TOKEN_SECRET);
                next();
            } catch (err) {
                res.status(403).json({ message: "Forbidden: Invalid or expired token" });
            }
        };

        const verifyAdmin = async (req, res, next) => {
            try {
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
                const user = await usersCollection.findOne({ email: req.user.email });
                if (!['admin', 'manager'].includes(user?.role)) {
                    return res.status(403).json({ message: "Forbidden: Manager or Admin only" });
                }
                next();
            } catch (err) {
                res.status(500).json({ message: "Server error during manager verification" });
            }
        };

        // ─────────────────────────────────────────────────────────────────────
        //  IMAGE UPLOAD APIs
        // ─────────────────────────────────────────────────────────────────────

        // Single image upload endpoint
        app.post('/api/upload', verifyToken, verifyManager, upload.single('image'), async (req, res) => {
            try {
                if (!req.file) {
                    return res.status(400).json({ message: 'No image file provided' });
                }
                
                const result = await uploadToCloudinary(req.file.buffer, 'cows');
                
                res.json({
                    success: true,
                    url: result.secure_url,
                    public_id: result.public_id
                });
            } catch (error) {
                console.error('Upload error:', error);
                res.status(500).json({ message: 'Image upload failed', error: error.message });
            }
        });

        // Multiple images upload endpoint
        app.post('/api/upload/multiple', verifyToken, verifyManager, upload.array('images', 10), async (req, res) => {
            try {
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
                console.error('Multiple upload error:', error);
                res.status(500).json({ message: 'Image upload failed', error: error.message });
            }
        });

        // Delete image from cloudinary
        app.delete('/api/upload/:public_id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { public_id } = req.params;
                await cloudinary.uploader.destroy(public_id);
                res.json({ success: true, message: 'Image deleted successfully' });
            } catch (error) {
                console.error('Delete error:', error);
                res.status(500).json({ message: 'Image deletion failed' });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  AUTH APIs
        // ─────────────────────────────────────────────────────────────────────

        // Email Register
        app.post('/auth/register', async (req, res) => {
            const { name, email, password } = req.body;

            if (!name || !email || !password) {
                return res.status(400).json({ message: "নাম, ইমেইল ও পাসওয়ার্ড দিন" });
            }
            if (password.length < 6) {
                return res.status(400).json({ message: "পাসওয়ার্ড কমপক্ষে ৬ অক্ষরের হতে হবে" });
            }

            try {
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
                const user = { ...newUser, _id: result.insertedId };

                const { password: _, ...safeUser } = user;

                const token = jwt.sign({ email: user.email, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: '7d' });
                setTokenCookie(res, token);
                res.status(201).json({ user: safeUser });

            } catch (error) {
                console.error("Register error:", error);
                res.status(500).json({ message: "অ্যাকাউন্ট তৈরি ব্যর্থ হয়েছে" });
            }
        });

        // Email Login
        app.post('/auth/login', async (req, res) => {
            const { email, password } = req.body;

            if (!email || !password) {
                return res.status(400).json({ message: "ইমেইল ও পাসওয়ার্ড দিন" });
            }

            try {
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

                const token = jwt.sign({ email: user.email, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: '7d' });
                setTokenCookie(res, token);
                res.json({ user: safeUser });

            } catch (error) {
                console.error("Login error:", error);
                res.status(500).json({ message: "লগইন ব্যর্থ হয়েছে" });
            }
        });

        // Google Login
        app.post('/auth/google', async (req, res) => {
            const { accessToken } = req.body;
            if (!accessToken) return res.status(400).json({ message: "No Google token found" });

            try {
                const googleRes = await axios.get(
                    `https://www.googleapis.com/oauth2/v3/userinfo?access_token=${accessToken}`
                );
                const { name, email, picture } = googleRes.data;

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

                const token = jwt.sign({ email: user.email, role: user.role }, ACCESS_TOKEN_SECRET, { expiresIn: '7d' });
                setTokenCookie(res, token);
                res.json({ user: safeUser });

            } catch (error) {
                console.error("Google login error:", error);
                res.status(400).json({ message: "Google verification failed" });
            }
        });

        // Session Refresh
        app.post('/auth/refresh', verifyToken, async (req, res) => {
            try {
                const user = await usersCollection.findOne({ email: req.user.email });
                if (!user) return res.status(404).json({ message: "User not found" });

                const { password: _, ...safeUser } = user;
                res.json({ user: safeUser });
            } catch (err) {
                res.status(403).json({ message: "Invalid or expired token" });
            }
        });

        // Logout
        app.post('/auth/logout', (req, res) => {
            res.clearCookie('token', {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
            }).json({ success: true });
        });

        // Current User
        app.get('/auth/me', verifyToken, async (req, res) => {
            try {
                const user = await usersCollection.findOne({ email: req.user.email });
                if (!user) return res.status(404).json({ message: "User not found" });
                const { password: _, ...safeUser } = user;
                res.json({ user: safeUser });
            } catch (err) {
                res.status(500).json({ message: "Server error" });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  USER APIs (Admin only)
        // ─────────────────────────────────────────────────────────────────────

        app.get('/api/users', verifyToken, verifyAdmin, async (req, res) => {
            try {
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
                console.error(err);
                res.status(500).json({ message: "Failed to fetch users" });
            }
        });

        app.post('/api/users/:id/roles', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const { id } = req.params;
                const { role } = req.body;

                if (!VALID_ROLES.includes(role)) {
                    return res.status(400).json({ message: `Invalid role. Valid roles: ${VALID_ROLES.join(', ')}` });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) return res.status(404).json({ message: "User not found" });

                await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role } }
                );

                res.json({ success: true, message: `Role added: ${role}` });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to add role" });
            }
        });

        app.delete('/api/users/:id/roles/:role', verifyToken, verifyAdmin, async (req, res) => {
            try {
                const { id, role } = req.params;

                if (role === 'user') {
                    return res.status(400).json({ message: "Cannot remove 'user' role" });
                }

                const user = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (!user) return res.status(404).json({ message: "User not found" });

                await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role: 'user' } }
                );

                res.json({ success: true, message: `Role removed: ${role}` });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to remove role" });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  COWS APIs
        // ─────────────────────────────────────────────────────────────────────

        // Get all cows
        app.get('/api/cows', async (req, res) => {
            try {
                const cows = await cowsCollection.find().toArray();
                res.json(cows);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to fetch cows" });
            }
        });

        // Get single cow
        app.get('/api/cows/:id', async (req, res) => {
            try {
                const { id } = req.params;
                const cow = await cowsCollection.findOne({ _id: new ObjectId(id) });
                if (!cow) return res.status(404).json({ message: "Cow not found" });
                res.json(cow);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch cow" });
            }
        });

        // Add new cow (admin/manager only)
        app.post('/api/cows', verifyToken, verifyManager, async (req, res) => {
            try {
                const cowData = {
                    ...req.body,
                    images: req.body.images || [],
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                };
                
                const result = await cowsCollection.insertOne(cowData);
                const newCow = { ...cowData, id: result.insertedId.toString(), _id: result.insertedId };
                res.status(201).json(newCow);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to add cow" });
            }
        });

        // Update cow (admin/manager only)
        app.put('/api/cows/:id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                const updateData = {
                    ...req.body,
                    updated_at: new Date().toISOString()
                };
                
                const result = await cowsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateData }
                );
                
                if (result.matchedCount === 0) {
                    return res.status(404).json({ message: "Cow not found" });
                }
                
                res.json({ success: true, message: "Cow updated successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to update cow" });
            }
        });

        // Delete cow (admin/manager only)
        app.delete('/api/cows/:id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                const result = await cowsCollection.deleteOne({ _id: new ObjectId(id) });
                
                if (result.deletedCount === 0) {
                    return res.status(404).json({ message: "Cow not found" });
                }
                
                res.json({ success: true, message: "Cow deleted successfully" });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to delete cow" });
            }
        });

        // Toggle featured status
        app.patch('/api/cows/:id/featured', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                const { featured } = req.body;
                
                await cowsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { featured } }
                );
                
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ message: "Failed to update featured status" });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  PRICE INDEX APIs
        // ─────────────────────────────────────────────────────────────────────

        app.get('/api/price-index', async (req, res) => {
            try {
                const prices = await priceIndexCollection.find().sort({ date: -1 }).toArray();
                res.json(prices);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to fetch price index" });
            }
        });

        app.post('/api/price-index', verifyToken, verifyManager, async (req, res) => {
            try {
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
                console.error(err);
                res.status(500).json({ message: "Failed to add price" });
            }
        });

        app.post('/api/smart-price', verifyToken, verifyManager, async (req, res) => {
            try {
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
                res.json({ newPrice: newPriceValue, changePercent: newPrice.change_percent, factors: newPrice.factors });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Smart price update failed" });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  ANNOUNCEMENTS APIs
        // ─────────────────────────────────────────────────────────────────────

        app.get('/api/announcements', async (req, res) => {
            try {
                const announcements = await announcementsCollection.find().sort({ created_at: -1 }).toArray();
                res.json(announcements);
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to fetch announcements" });
            }
        });

        app.get('/api/announcements/active', async (req, res) => {
            try {
                const now = new Date().toISOString();
                const activeAnnouncements = await announcementsCollection.find({
                    active: true,
                    $or: [
                        { end_date: null },
                        { end_date: { $gte: now } }
                    ]
                }).sort({ priority: -1, created_at: -1 }).toArray();
                res.json(activeAnnouncements);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch active announcements" });
            }
        });

        app.post('/api/announcements', verifyToken, verifyManager, async (req, res) => {
            try {
                const announcement = {
                    ...req.body,
                    created_at: new Date().toISOString(),
                    updated_at: new Date().toISOString()
                };
                const result = await announcementsCollection.insertOne(announcement);
                res.status(201).json({ ...announcement, _id: result.insertedId });
            } catch (err) {
                console.error(err);
                res.status(500).json({ message: "Failed to add announcement" });
            }
        });

        app.put('/api/announcements/:id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                const updateData = {
                    ...req.body,
                    updated_at: new Date().toISOString()
                };
                
                await announcementsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: updateData }
                );
                
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ message: "Failed to update announcement" });
            }
        });

        app.delete('/api/announcements/:id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                await announcementsCollection.deleteOne({ _id: new ObjectId(id) });
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ message: "Failed to delete announcement" });
            }
        });

        // ─────────────────────────────────────────────────────────────────────
        //  TESTIMONIALS APIs
        // ─────────────────────────────────────────────────────────────────────

        app.get('/api/testimonials', async (req, res) => {
            try {
                const testimonials = await testimonialsCollection.find().sort({ created_at: -1 }).toArray();
                res.json(testimonials);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch testimonials" });
            }
        });

        app.get('/api/testimonials/approved', async (req, res) => {
            try {
                const approved = await testimonialsCollection.find({ approved: true }).sort({ created_at: -1 }).toArray();
                res.json(approved);
            } catch (err) {
                res.status(500).json({ message: "Failed to fetch approved testimonials" });
            }
        });

        app.post('/api/testimonials', verifyToken, verifyManager, async (req, res) => {
            try {
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
                const { id } = req.params;
                await testimonialsCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: req.body }
                );
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ message: "Failed to update testimonial" });
            }
        });

        app.delete('/api/testimonials/:id', verifyToken, verifyManager, async (req, res) => {
            try {
                const { id } = req.params;
                await testimonialsCollection.deleteOne({ _id: new ObjectId(id) });
                res.json({ success: true });
            } catch (err) {
                res.status(500).json({ message: "Failed to delete testimonial" });
            }
        });

        app.get('/api/admin/stats', verifyToken, verifyAdmin, async (req, res) => {
            try {
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

        console.log("✅ All API endpoints are ready!");
        console.log("📸 Image upload with Cloudinary is configured");

    } catch (error) {
        console.error("Run function error:", error);
    }
}

run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('BCI Backend Server is Running with Image Upload Support');
});

app.listen(port, () => {
    console.log(`🚀 Server is running on port ${port}`);
});