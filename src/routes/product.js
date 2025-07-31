// routes/productRoutes.js
const express = require('express');
const productRoutes = express.Router();
const { Product } = require('../modles/product'); // path change as needed

// =================== POST - Create a product ===================
productRoutes.post('/addProduct', async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json({ message: "Product created successfully", product });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =================== GET - All products ===================
productRoutes.get('/getProduct', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =================== GET - Single product by ID ===================
productRoutes.get('/getUniqureProduct/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Product not found" });
    res.json(product);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =================== PUT - Update product ===================
productRoutes.put('/updateProduct/:id', async (req, res) => {
  try {
    const updated = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
    if (!updated) return res.status(404).json({ message: "Product not found" });
    res.json({ message: "Product updated", updated });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// =================== DELETE - Remove product ===================
productRoutes.delete('/deleteProduct/:id', async (req, res) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) return res.status(404).json({ message: "Product not found" });
    res.json({ message: "Product deleted" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = productRoutes;
