// ==================== KONFIGURASI AWAL ====================
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ==================== KONEKSI DATABASE ====================
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
}).promise();

// ==================== MIDDLEWARE AUTH ====================
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Token tidak ditemukan' });
    
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Token tidak valid' });
    }
};

const verifyRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Akses ditolak' });
        }
        next();
    };
};

// ==================== ENDPOINT 1: AUTH ====================
app.post('/api/auth/register', async (req, res) => {
    const { full_name, email, phone, password, role } = req.body;
    if (!full_name || !email || !phone || !password) {
        return res.status(400).json({ message: 'Semua field wajib diisi' });
    }

    try {
        const hashed = await bcrypt.hash(password, 10);
        const [result] = await db.query(
            'INSERT INTO users (full_name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)',
            [full_name, email, phone, hashed, role || 'customer']
        );
        res.status(201).json({ message: 'Registrasi berhasil', user_id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ message: 'Email atau No HP sudah terdaftar' });
        }
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email dan password wajib diisi' });
    }

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Email tidak ditemukan' });
        }

        const user = rows[0];
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ message: 'Password salah' });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login sukses',
            token,
            user: { id: user.id, full_name: user.full_name, email: user.email, role: user.role }
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ==================== ENDPOINT 2: JENIS PAKAIAN (PUBLIK) ====================
app.get('/api/item-types', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT * FROM item_types WHERE is_active = 1');
        res.json(rows);
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ==================== ENDPOINT 3: CUSTOMER (BUAT PESANAN) ====================
app.post('/api/customer/order/create', verifyToken, verifyRole(['customer']), async (req, res) => {
    const { items, pickup_address, delivery_address, scheduled_pickup_at, notes } = req.body;
    const customer_id = req.user.id;

    if (!items || items.length === 0 || !pickup_address || !scheduled_pickup_at) {
        return res.status(400).json({ message: 'Items, alamat, dan jadwal wajib diisi' });
    }

    try {
        let total_price = 0;
        let total_items = 0;
        const orderItems = [];

        // Hitung total harga
        for (const item of items) {
            const [typeRows] = await db.query('SELECT * FROM item_types WHERE id = ?', [item.item_type_id]);
            if (typeRows.length === 0) {
                return res.status(400).json({ message: `Jenis pakaian ID ${item.item_type_id} tidak ditemukan` });
            }
            const type = typeRows[0];
            const price = item.is_express ? type.price_express : type.price_per_item;
            const subtotal = price * item.quantity;
            
            total_price += subtotal;
            total_items += item.quantity;
            
            orderItems.push({
                item_type_id: item.item_type_id,
                quantity: item.quantity,
                price_per_item: price,
                is_express: item.is_express || 0,
                extra_fragrance: item.extra_fragrance || 0,
                subtotal: subtotal,
                notes: item.notes || null
            });
        }

        // Biaya ongkir (jika kurang dari 5 item)
        let shipping_cost = 0;
        if (total_items < 5) shipping_cost = 15000; // Contoh ongkir flat

        const grand_total = total_price + shipping_cost;
        const order_code = `ZV-${Date.now().toString().slice(-8)}`;

        // Insert ke tabel orders
        const [orderResult] = await db.query(
            `INSERT INTO orders 
            (order_code, customer_id, pickup_address, delivery_address, scheduled_pickup_at, 
             total_items, total_price, shipping_cost, grand_total, notes, status) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
            [order_code, customer_id, pickup_address, delivery_address || pickup_address, 
             scheduled_pickup_at, total_items, total_price, shipping_cost, grand_total, notes]
        );

        const order_id = orderResult.insertId;

        // Insert detail items
        for (const item of orderItems) {
            await db.query(
                `INSERT INTO order_items 
                (order_id, item_type_id, quantity, price_per_item, is_express, extra_fragrance, subtotal, notes) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [order_id, item.item_type_id, item.quantity, item.price_per_item, 
                 item.is_express, item.extra_fragrance, item.subtotal, item.notes]
            );
        }

        // Kirim notifikasi ke semua freelancer yang aktif (simulasi)
        // (Di sini bisa integrasi FCM)

        res.status(201).json({
            message: 'Pesanan berhasil dibuat! Menunggu mitra setrika.',
            order_id: order_id,
            order_code: order_code,
            grand_total: grand_total
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Gagal membuat pesanan', error: err.message });
    }
});

// ==================== ENDPOINT 4: CUSTOMER (TRACKING) ====================
app.get('/api/customer/order/tracking/:id', verifyToken, verifyRole(['customer']), async (req, res) => {
    const orderId = req.params.id;
    try {
        const [orders] = await db.query(
            `SELECT o.*, u.full_name as freelancer_name, u.phone as freelancer_phone 
             FROM orders o 
             LEFT JOIN users u ON o.freelancer_id = u.id 
             WHERE o.id = ? AND o.customer_id = ?`,
            [orderId, req.user.id]
        );
        
        if (orders.length === 0) {
            return res.status(404).json({ message: 'Pesanan tidak ditemukan' });
        }

        const order = orders[0];
        // Definisikan timeline berdasarkan status
        const statusMap = {
            'pending': 'Menunggu Freelancer',
            'assigned': 'Freelancer Ditugaskan',
            'picked_up': 'Pakaian Dijemput',
            'processing': 'Sedang Disetrika',
            'ready': 'Siap Diantar',
            'delivered': 'Selesai Diantar',
            'cancelled': 'Dibatalkan'
        };

        res.json({
            order_code: order.order_code,
            status: order.status,
            status_label: statusMap[order.status] || order.status,
            freelancer: order.freelancer_name || 'Belum ada mitra',
            freelancer_phone: order.freelancer_phone || '-',
            scheduled_pickup: order.scheduled_pickup_at,
            grand_total: order.grand_total,
            notes: order.notes
        });

    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ==================== ENDPOINT 5: FREELANCER (DASHBOARD & STATUS) ====================
app.get('/api/freelancer/dashboard', verifyToken, verifyRole(['freelancer']), async (req, res) => {
    const freelancer_id = req.user.id;
    try {
        // Pesanan pending yang bisa diambil
        const [pending] = await db.query(
            `SELECT o.*, u.full_name as customer_name, u.phone as customer_phone 
             FROM orders o 
             JOIN users u ON o.customer_id = u.id 
             WHERE o.status = 'pending'`
        );

        // Tugas yang sedang dikerjakan oleh freelancer ini
        const [myTasks] = await db.query(
            `SELECT o.*, u.full_name as customer_name 
             FROM orders o 
             JOIN users u ON o.customer_id = u.id 
             WHERE o.freelancer_id = ? AND o.status NOT IN ('delivered', 'cancelled')`,
            [freelancer_id]
        );

        // Pendapatan hari ini
        const [earnings] = await db.query(
            `SELECT COALESCE(SUM(freelancer_earning), 0) as total_today 
             FROM transactions 
             WHERE freelancer_id = ? AND DATE(payment_date) = CURDATE()`,
            [freelancer_id]
        );

        res.json({
            pending_orders: pending,
            my_tasks: myTasks,
            earnings_today: earnings[0].total_today || 0
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// **INI ENDPOINT PALING PENTING: UPDATE STATUS (Freelancer)**
app.put('/api/freelancer/order/status', verifyToken, verifyRole(['freelancer']), async (req, res) => {
    const { order_id, status } = req.body;
    const freelancer_id = req.user.id;

    const validStatus = ['assigned', 'picked_up', 'processing', 'ready', 'delivered'];
    if (!validStatus.includes(status)) {
        return res.status(400).json({ message: 'Status tidak valid' });
    }

    try {
        // Cek apakah order ini milik freelancer ini atau masih pending
        const [orderCheck] = await db.query(
            'SELECT * FROM orders WHERE id = ?', [order_id]
        );
        if (orderCheck.length === 0) {
            return res.status(404).json({ message: 'Pesanan tidak ditemukan' });
        }

        const order = orderCheck[0];

        // Jika status 'assigned', freelancer mengambil pesanan
        if (status === 'assigned') {
            if (order.status !== 'pending') {
                return res.status(400).json({ message: 'Pesanan sudah diambil oleh mitra lain' });
            }
            await db.query(
                'UPDATE orders SET freelancer_id = ?, status = ? WHERE id = ?',
                [freelancer_id, status, order_id]
            );
            return res.json({ message: 'Berhasil mengambil pesanan', new_status: status });
        }

        // Untuk status lain, pastikan pesanan ini milik freelancer yang login
        if (order.freelancer_id !== freelancer_id) {
            return res.status(403).json({ message: 'Anda tidak berhak mengubah pesanan ini' });
        }

        // Update status
        await db.query('UPDATE orders SET status = ? WHERE id = ?', [status, order_id]);

        // Jika status delivered, otomatis hitung komisi dan simpan ke transaksi
        if (status === 'delivered') {
            const commission = Math.floor(order.grand_total * 0.3);
            const freelancerEarn = order.grand_total - commission;
            await db.query(
                `INSERT INTO transactions (order_id, freelancer_id, customer_id, total_order_amount, platform_commission, freelancer_earning, status, payment_date) 
                 VALUES (?, ?, ?, ?, ?, ?, 'success', NOW())`,
                [order_id, freelancer_id, order.customer_id, order.grand_total, commission, freelancerEarn]
            );
        }

        res.json({ 
            message: `Status berhasil diupdate menjadi ${status}`,
            new_status: status
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Gagal update status', error: err.message });
    }
});

// ==================== ENDPOINT 6: ADMIN (STATS) ====================
app.get('/api/admin/dashboard/stats', verifyToken, verifyRole(['admin']), async (req, res) => {
    try {
        const [totalOrders] = await db.query('SELECT COUNT(*) as total FROM orders');
        const [pendingOrders] = await db.query('SELECT COUNT(*) as pending FROM orders WHERE status = "pending"');
        const [totalEarnings] = await db.query('SELECT COALESCE(SUM(platform_commission), 0) as income FROM transactions');
        const [activeFreelancers] = await db.query('SELECT COUNT(*) as active FROM freelancer_profiles WHERE status = "active"');

        res.json({
            total_orders: totalOrders[0].total,
            pending_orders: pendingOrders[0].pending,
            total_income: totalEarnings[0].income,
            active_freelancers: activeFreelancers[0].active
        });
    } catch (err) {
        res.status(500).json({ message: 'Server error', error: err.message });
    }
});

// ==================== JALANKAN SERVER ====================
app.listen(PORT, () => {
    console.log(`🚀 Server Zeevanna berjalan di http://localhost:${PORT}`);
    console.log('📦 Database terhubung!');
});
