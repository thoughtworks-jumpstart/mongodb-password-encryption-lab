const mongoose = require('mongoose');
mongoose.connect(global.__MONGO_URI__, { useNewUrlParser: true });
