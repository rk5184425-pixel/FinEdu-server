const mongoose = require('mongoose');

// Document schema
const documentSchema = new mongoose.Schema({
  filename: String,
  hash: String,
  walletAddress: String,
  timestamp: Number,
  size: Number,
  type: String,
});
const Document = mongoose.model('Document', documentSchema);

module.exports = function(app) {
  // Save document
  app.post('/api/documents', async (req, res) => {
    try {
      const doc = new Document(req.body);
      await doc.save();
      res.status(201).json(doc);
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  });

  // Get all documents (optionally by wallet)
  app.get('/api/documents', async (req, res) => {
    try {
      const { walletAddress } = req.query;
      let docs;
      if (walletAddress) {
        docs = await Document.find({ walletAddress: { $regex: new RegExp('^' + walletAddress + '$', 'i') } });
      } else {
        docs = await Document.find();
      }
      res.json(docs);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Get document by hash
  app.get('/api/documents/hash/:hash', async (req, res) => {
    try {
      const hash = req.params.hash.trim().toLowerCase();
      const doc = await Document.findOne({ hash: { $regex: new RegExp('^' + hash + '$', 'i') } });
      if (!doc) return res.status(404).json({ error: 'Not found' });
      res.json(doc);
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // Delete document by id
  app.delete('/api/documents/:id', async (req, res) => {
    try {
      const { id } = req.params;
      await Document.findByIdAndDelete(id);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });
}; 