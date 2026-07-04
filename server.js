const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/linkify';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// ==================== SCHEMAS ====================

// User Schema
const userSchema = new mongoose.Schema({
  userId: { type: String, unique: true, default: () => uuidv4() },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  dateJoined: { type: Date, default: Date.now },
  accountStatus: { type: String, enum: ['active', 'suspended', 'banned'], default: 'active' },
  isVerified: { type: Boolean, default: false },
  anonymousProfile: {
    anonymousName: { type: String, unique: true, sparse: true },
    anonymousAvatar: { type: String, default: null },
    isIdentityRevealed: { type: Boolean, default: false }
  }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Profile Schema
const profileSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  displayName: String,
  ageRange: { type: String, enum: ['13-17', '18-20', '21-25', '26-30', '31+'] },
  gender: String,
  country: String,
  stateRegion: String,
  preferredLanguage: String,
  bio: { type: String, maxlength: 500 },
  academicInfo: {
    status: { type: String, enum: ['in-school', 'graduate', 'not-in-school'] },
    institutionName: String,
    academicLevel: String,
    faculty: String,
    department: String
  },
  personality: {
    introvertExtrovert: { type: Number, min: 0, max: 100 },
    seriousFun: { type: Number, min: 0, max: 100 },
    leaderFollower: { type: Number, min: 0, max: 100 },
    morningNight: { type: Number, min: 0, max: 100 },
    talkativeReserved: { type: Number, min: 0, max: 100 },
    textVoice: { type: Number, min: 0, max: 100 }
  }
}, { timestamps: true });

const Profile = mongoose.model('Profile', profileSchema);

// Preferences Schema
const preferencesSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  lookingFor: [{ type: String, enum: ['friendship', 'study-partner', 'networking', 'gaming-partner', 'group-chat', 'random-chat'] }],
  preferredAgeRange: String,
  preferredGender: String,
  preferredLocation: { type: String, enum: ['same-country', 'same-region', 'global'] },
  academicMatchFilters: [{ type: String, enum: ['same-institution', 'same-academic-level', 'same-faculty', 'same-department'] }],
  discoveryEnabled: { type: Boolean, default: true }
});

const Preferences = mongoose.model('Preferences', preferencesSchema);

// Interests Schema
const interestsSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  selectedInterests: [{ type: String }]
});

const Interests = mongoose.model('Interests', interestsSchema);

// Match Schema
const matchSchema = new mongoose.Schema({
  matchId: { type: String, unique: true, default: () => uuidv4() },
  user1: { type: String, required: true },
  user2: { type: String, required: true },
  compatibilityScore: { type: Number, default: 0 },
  scoreBreakdown: {
    interestMatch: Number,
    ageCompatibility: Number,
    languageMatch: Number,
    personalityMatch: Number,
    locationMatch: Number,
    academicMatch: Number
  },
  status: { type: String, enum: ['pending', 'active', 'blocked', 'ended'], default: 'pending' },
  user1Liked: { type: Boolean, default: false },
  user2Liked: { type: Boolean, default: false },
  matchedAt: { type: Date, default: Date.now },
  chatId: String,
  identityReveal: {
    user1Requested: { type: Boolean, default: false },
    user2Requested: { type: Boolean, default: false },
    user1Consented: { type: Boolean, default: false },
    user2Consented: { type: Boolean, default: false },
    revealedAt: Date
  }
}, { timestamps: true });

const Match = mongoose.model('Match', matchSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
  chatId: { type: String, unique: true, default: () => uuidv4() },
  participants: [{ type: String }],
  messages: [{
    messageId: { type: String, default: () => uuidv4() },
    senderId: String,
    senderAnonymousName: String,
    content: String,
    contentType: { type: String, enum: ['text', 'image', 'voice', 'file'], default: 'text' },
    mediaUrl: String,
    timestamp: { type: Date, default: Date.now },
    isRead: { type: Boolean, default: false }
  }],
  lastMessage: {
    content: String,
    senderId: String,
    timestamp: Date
  }
}, { timestamps: true });

const Chat = mongoose.model('Chat', chatSchema);

// Report Schema
const reportSchema = new mongoose.Schema({
  reportId: { type: String, unique: true, default: () => uuidv4() },
  reporterId: String,
  reportedUserId: String,
  matchId: String,
  chatId: String,
  messageId: String,
  reason: { type: String, enum: ['harassment', 'spam', 'fake-account', 'inappropriate-content', 'other'] },
  description: String,
  status: { type: String, enum: ['pending', 'under-review', 'resolved', 'dismissed'], default: 'pending' },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' }
}, { timestamps: true });

const Report = mongoose.model('Report', reportSchema);

// Block Schema
const blockSchema = new mongoose.Schema({
  blockerId: String,
  blockedId: String,
  reason: String,
  createdAt: { type: Date, default: Date.now }
});

const Block = mongoose.model('Block', blockSchema);

// ==================== MIDDLEWARE ====================

const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==================== HELPER FUNCTIONS ====================

const generateAnonymousName = () => {
  const adjectives = ['Blue', 'Swift', 'Happy', 'Clever', 'Bright', 'Cool', 'Wild', 'Calm', 'Bold', 'Quiet'];
  const animals = ['Panda', 'Fox', 'Wolf', 'Eagle', 'Tiger', 'Bear', 'Hawk', 'Lion', 'Owl', 'Deer'];
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const animal = animals[Math.floor(Math.random() * animals.length)];
  const num = Math.floor(Math.random() * 999) + 1;
  return `${adj}${animal}${num}`;
};

const calculateCompatibilityScore = (userA, userB) => {
  let score = 0;
  const breakdown = {};

  // Interest Match (max 40)
  const commonInterests = userA.interests?.filter(i => userB.interests?.includes(i)) || [];
  breakdown.interestMatch = Math.min(commonInterests.length * 10, 40);
  score += breakdown.interestMatch;

  // Age Compatibility (max 20)
  breakdown.ageCompatibility = (userA.profile?.ageRange === userB.profile?.ageRange) ? 20 : 0;
  score += breakdown.ageCompatibility;

  // Language Match (max 20)
  breakdown.languageMatch = (userA.profile?.preferredLanguage === userB.profile?.preferredLanguage) ? 20 : 0;
  score += breakdown.languageMatch;

  // Personality Match (max 20)
  const pA = userA.profile?.personality || {};
  const pB = userB.profile?.personality || {};
  const diff = Math.sqrt(
    Math.pow((pA.introvertExtrovert || 50) - (pB.introvertExtrovert || 50), 2) +
    Math.pow((pA.seriousFun || 50) - (pB.seriousFun || 50), 2) +
    Math.pow((pA.leaderFollower || 50) - (pB.leaderFollower || 50), 2) +
    Math.pow((pA.morningNight || 50) - (pB.morningNight || 50), 2) +
    Math.pow((pA.talkativeReserved || 50) - (pB.talkativeReserved || 50), 2) +
    Math.pow((pA.textVoice || 50) - (pB.textVoice || 50), 2)
  );
  breakdown.personalityMatch = Math.round((1 - (diff / 245)) * 20);
  score += breakdown.personalityMatch;

  // Location Match (max 10)
  if (userA.profile?.country === userB.profile?.country) {
    breakdown.locationMatch = 10;
  } else if (userA.profile?.stateRegion === userB.profile?.stateRegion) {
    breakdown.locationMatch = 5;
  } else {
    breakdown.locationMatch = 0;
  }
  score += breakdown.locationMatch;

  // Academic Match (max 35)
  breakdown.academicMatch = 0;
  const acadA = userA.profile?.academicInfo || {};
  const acadB = userB.profile?.academicInfo || {};
  if (acadA.institutionName && acadA.institutionName === acadB.institutionName) breakdown.academicMatch += 15;
  if (acadA.academicLevel && acadA.academicLevel === acadB.academicLevel) breakdown.academicMatch += 10;
  if (acadA.department && acadA.department === acadB.department) breakdown.academicMatch += 10;
  score += breakdown.academicMatch;

  return { total: Math.min(score, 100), breakdown, commonInterests };
};

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be 8+ characters' });
    }

    // Check existing
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);

    // Generate anonymous name
    let anonymousName = generateAnonymousName();
    let nameExists = await User.findOne({ 'anonymousProfile.anonymousName': anonymousName });
    while (nameExists) {
      anonymousName = generateAnonymousName();
      nameExists = await User.findOne({ 'anonymousProfile.anonymousName': anonymousName });
    }

    // Create user
    const user = new User({
      username,
      email,
      passwordHash,
      anonymousProfile: { anonymousName }
    });
    await user.save();

    // Create empty profile, preferences, interests
    await Profile.create({ userId: user.userId });
    await Preferences.create({ userId: user.userId });
    await Interests.create({ userId: user.userId, selectedInterests: [] });

    // Generate token
    const token = jwt.sign(
      { userId: user.userId, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        anonymousName: user.anonymousProfile.anonymousName
      },
      token
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    if (user.accountStatus !== 'active') {
      return res.status(403).json({ error: 'Account suspended or banned' });
    }

    const token = jwt.sign(
      { userId: user.userId, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        anonymousName: user.anonymousProfile.anonymousName
      },
      token
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== PROFILE ROUTES ====================

// Get my profile
app.get('/api/profiles/me', authenticate, async (req, res) => {
  try {
    const profile = await Profile.findOne({ userId: req.userId });
    const preferences = await Preferences.findOne({ userId: req.userId });
    const interests = await Interests.findOne({ userId: req.userId });

    res.json({ profile, preferences, interests });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update profile
app.put('/api/profiles/me', authenticate, async (req, res) => {
  try {
    const updates = req.body;
    const profile = await Profile.findOneAndUpdate(
      { userId: req.userId },
      { $set: updates },
      { new: true, upsert: true }
    );
    res.json({ message: 'Profile updated', profile });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update preferences
app.put('/api/preferences/me', authenticate, async (req, res) => {
  try {
    const preferences = await Preferences.findOneAndUpdate(
      { userId: req.userId },
      { $set: req.body },
      { new: true, upsert: true }
    );
    res.json({ message: 'Preferences updated', preferences });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Update interests
app.put('/api/interests/me', authenticate, async (req, res) => {
  try {
    const { selectedInterests } = req.body;
    const interests = await Interests.findOneAndUpdate(
      { userId: req.userId },
      { $set: { selectedInterests } },
      { new: true, upsert: true }
    );
    res.json({ message: 'Interests updated', interests });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== MATCHMAKING ROUTES ====================

// Discover potential matches
app.post('/api/matches/discover', authenticate, async (req, res) => {
  try {
    const { limit = 20, offset = 0 } = req.body;

    // Get current user's data
    const myProfile = await Profile.findOne({ userId: req.userId });
    const myPreferences = await Preferences.findOne({ userId: req.userId });
    const myInterests = await Interests.findOne({ userId: req.userId });

    if (!myProfile) {
      return res.status(400).json({ error: 'Complete your profile first' });
    }

    // Find existing matches to exclude
    const existingMatches = await Match.find({
      $or: [{ user1: req.userId }, { user2: req.userId }]
    });
    const matchedUserIds = existingMatches.map(m => 
      m.user1 === req.userId ? m.user2 : m.user1
    );

    // Find blocked users to exclude
    const blocks = await Block.find({
      $or: [{ blockerId: req.userId }, { blockedId: req.userId }]
    });
    const blockedIds = blocks.map(b => 
      b.blockerId === req.userId ? b.blockedId : b.blockerId
    );

    const excludeIds = [...matchedUserIds, ...blockedIds, req.userId];

    // Build query based on preferences
    let query = { userId: { $nin: excludeIds } };

    // Location filter
    if (myPreferences?.preferredLocation === 'same-country') {
      query['country'] = myProfile.country;
    }

    // Age filter
    if (myPreferences?.preferredAgeRange) {
      query['ageRange'] = myPreferences.preferredAgeRange;
    }

    // Find potential matches
    const profiles = await Profile.find(query)
      .limit(limit)
      .skip(offset);

    // Calculate scores
    const matches = [];
    for (const profile of profiles) {
      const theirInterests = await Interests.findOne({ userId: profile.userId });
      const theirPreferences = await Preferences.findOne({ userId: profile.userId });

      const userA = {
        profile: myProfile,
        interests: myInterests?.selectedInterests || []
      };
      const userB = {
        profile: profile,
        interests: theirInterests?.selectedInterests || []
      };

      const score = calculateCompatibilityScore(userA, userB);

      // Get anonymous name
      const theirUser = await User.findOne({ userId: profile.userId });

      matches.push({
        userId: profile.userId,
        anonymousName: theirUser?.anonymousProfile?.anonymousName || 'Anonymous',
        anonymousAvatar: theirUser?.anonymousProfile?.anonymousAvatar,
        compatibilityScore: score.total,
        scoreBreakdown: score.breakdown,
        commonInterests: score.commonInterests,
        ageRange: profile.ageRange,
        country: profile.country,
        academicLevel: profile.academicInfo?.academicLevel,
        bio: profile.bio
      });
    }

    // Sort by score descending
    matches.sort((a, b) => b.compatibilityScore - a.compatibilityScore);

    res.json({
      matches,
      total: matches.length,
      hasMore: matches.length === limit
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Like/swiping
app.post('/api/matches/swipe', authenticate, async (req, res) => {
  try {
    const { targetUserId, action } = req.body; // action: 'like' or 'pass'

    if (action === 'pass') {
      return res.json({ message: 'Passed' });
    }

    // Check if target already liked current user
    const existingMatch = await Match.findOne({
      $or: [
        { user1: targetUserId, user2: req.userId },
        { user1: req.userId, user2: targetUserId }
      ]
    });

    if (existingMatch) {
      // Mutual like - it's a match!
      if (existingMatch.user1 === targetUserId && !existingMatch.user1Liked) {
        existingMatch.user1Liked = true;
        existingMatch.status = 'active';

        // Create chat
        const chat = new Chat({
          participants: [req.userId, targetUserId]
        });
        await chat.save();
        existingMatch.chatId = chat.chatId;

        await existingMatch.save();

        return res.json({
          message: "It's a Match!",
          isMatch: true,
          match: existingMatch,
          chatId: chat.chatId
        });
      }

      return res.json({ message: 'Already interacted' });
    }

    // Create new match (pending)
    const match = new Match({
      user1: req.userId,
      user2: targetUserId,
      user1Liked: true,
      status: 'pending'
    });
    await match.save();

    res.json({ message: 'Liked', match });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get my matches
app.get('/api/matches', authenticate, async (req, res) => {
  try {
    const matches = await Match.find({
      $or: [{ user1: req.userId }, { user2: req.userId }],
      status: 'active'
    }).sort({ matchedAt: -1 });

    res.json({ matches });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== CHAT ROUTES ====================

// Get chat messages
app.get('/api/chats/:chatId', authenticate, async (req, res) => {
  try {
    const chat = await Chat.findOne({
      chatId: req.params.chatId,
      participants: req.userId
    });

    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    res.json({ chat });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Send message
app.post('/api/chats/:chatId/messages', authenticate, async (req, res) => {
  try {
    const { content } = req.body;
    const chat = await Chat.findOne({
      chatId: req.params.chatId,
      participants: req.userId
    });

    if (!chat) return res.status(404).json({ error: 'Chat not found' });

    // Get sender's anonymous name
    const user = await User.findOne({ userId: req.userId });

    const message = {
      senderId: req.userId,
      senderAnonymousName: user?.anonymousProfile?.anonymousName || 'Anonymous',
      content,
      timestamp: new Date()
    };

    chat.messages.push(message);
    chat.lastMessage = {
      content,
      senderId: req.userId,
      timestamp: new Date()
    };

    await chat.save();

    res.json({ message: 'Message sent', chatMessage: message });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SAFETY ROUTES ====================

// Report user
app.post('/api/safety/report', authenticate, async (req, res) => {
  try {
    const { reportedUserId, reason, description, matchId, chatId } = req.body;

    const report = new Report({
      reporterId: req.userId,
      reportedUserId,
      reason,
      description,
      matchId,
      chatId
    });
    await report.save();

    res.json({ message: 'Report submitted', report });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Block user
app.post('/api/safety/block', authenticate, async (req, res) => {
  try {
    const { blockedId, reason } = req.body;

    const block = new Block({
      blockerId: req.userId,
      blockedId,
      reason
    });
    await block.save();

    // End any active match
    await Match.updateOne(
      {
        $or: [
          { user1: req.userId, user2: blockedId },
          { user1: blockedId, user2: req.userId }
        ]
      },
      { $set: { status: 'blocked' } }
    );

    res.json({ message: 'User blocked' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get blocked users
app.get('/api/safety/blocked', authenticate, async (req, res) => {
  try {
    const blocks = await Block.find({ blockerId: req.userId });
    res.json({ blockedUsers: blocks });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Root
app.get('/', (req, res) => {
  res.json({ message: 'Linkify API is running' });
});

// ==================== START SERVER ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Linkify server running on port ${PORT}`);
});
