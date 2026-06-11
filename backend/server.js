const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MercadoPagoConfig, Preference } = require('mercadopago');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Configuração do Mercado Pago (NOVA API)
const client = new MercadoPagoConfig({ 
    accessToken: process.env.MERCADO_PAGO_ACCESS_TOKEN,
    options: {
        timeout: 5000,
        idempotencyKey: 'abc',
        headers: {
            'X-Platform-Id': 'backend'
        }
    }
});

// Configuração do banco de dados Supabase
const pool = new Pool({
    connectionString: process.env.SUPABASE_DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Middlewares
app.use(cors({
    origin: ['https://dropsetnutri.netlify.app', 'http://localhost:3000', 'http://localhost:5500'],
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Teste de conexão
app.get('/api/test', async (req, res) => {
    try {
        const client = await pool.connect();
        await client.query('SELECT NOW()');
        client.release();
        res.json({ status: 'OK', message: 'Servidor e banco conectados!' });
    } catch (error) {
        res.status(500).json({ status: 'ERROR', message: error.message });
    }
});

// ==================== AUTENTICAÇÃO ====================

// Registro
app.post('/api/registro', async (req, res) => {
    try {
        const { nome, email, telefone, senha } = req.body;
        
        if (!nome || !email || !senha) {
            return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios' });
        }

        const hashedSenha = await bcrypt.hash(senha, 10);
        
        // CORREÇÃO: senha -> senha_hash
        const result = await pool.query(
            'INSERT INTO usuarios (nome, email, telefone, senha_hash) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, telefone, created_at',
            [nome, email, telefone || null, hashedSenha]
        );

        const usuario = result.rows[0];
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'dropset2025seguro!',
            { expiresIn: '7d' }
        );

        console.log('✅ Registro realizado:', email);
        res.status(201).json({ 
            mensagem: 'Usuário criado com sucesso',
            usuario,
            token
        });
    } catch (error) {
        console.error('❌ ERRO NO REGISTRO:', error.message);
        if (error.code === '23505') {
            res.status(409).json({ erro: 'Email já cadastrado' });
        } else {
            res.status(500).json({ erro: 'Erro interno ao registrar' });
        }
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, senha } = req.body;

        if (!email || !senha) {
            return res.status(400).json({ erro: 'Email e senha são obrigatórios' });
        }

        // CORREÇÃO: senha -> senha_hash
        const result = await pool.query(
            'SELECT id, nome, email, telefone, senha_hash, created_at FROM usuarios WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ erro: 'Email ou senha inválidos' });
        }

        const usuario = result.rows[0];
        // CORREÇÃO: usuario.senha -> usuario.senha_hash
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaValida) {
            return res.status(401).json({ erro: 'Email ou senha inválidos' });
        }

        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'dropset2025seguro!',
            { expiresIn: '7d' }
        );

        // CORREÇÃO: delete usuario.senha -> delete usuario.senha_hash
        delete usuario.senha_hash;

        console.log('✅ Login realizado:', email);
        res.json({ 
            mensagem: 'Login realizado com sucesso',
            usuario,
            token
        });
    } catch (error) {
        console.error('❌ ERRO NO LOGIN:', error.message);
        res.status(500).json({ erro: 'Erro interno ao fazer login' });
    }
});

// Middleware de autenticação
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ erro: 'Token não fornecido' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'dropset2025seguro!', (err, usuario) => {
        if (err) {
            return res.status(403).json({ erro: 'Token inválido ou expirado' });
        }
        req.usuario = usuario;
        next();
    });
}

// ==================== PRODUTOS ====================

// Listar produtos
app.get('/api/produtos', async (req, res) => {
    try {
        const { q, categoria } = req.query;
        
        console.log('🔍 Recebido request:', { q, categoria });

        let query = 'SELECT * FROM produtos WHERE estoque > 0';
        const values = [];

        if (categoria) {
            query += ' AND categoria = $1';
            values.push(categoria);
        }

        if (q) {
            query += ` AND (LOWER(nome) LIKE $${values.length + 1} OR LOWER(descricao) LIKE $${values.length + 1})`;
            values.push(`%${q.toLowerCase()}%`);
        }

        query += ' ORDER BY nome ASC';
        
        console.log(' Query final:', query);
        console.log(' Valores:', values);

        const result = await pool.query(query, values);
        console.log(`✅ Produtos encontrados: ${result.rows.length}`);
        
        res.json(result.rows);
    } catch (error) {
        console.error('❌ ERRO AO BUSCAR PRODUTOS:', error.message);
        res.status(500).json({ erro: 'Erro ao buscar produtos', details: error.message });
    }
});

// ==================== PEDIDOS ====================

// Criar pedido
app.post('/api/pedidos', autenticarToken, async (req, res) => {
    try {
        const { carrinho, total } = req.body;
        const userId = req.usuario.id;

        const result = await pool.query(
            'INSERT INTO pedidos (user_id, itens, total, status) VALUES ($1, $2, $3, $4) RETURNING *',
            [userId, JSON.stringify(carrinho), total, 'pendente']
        );

        console.log('📦 Pedido criado:', result.rows[0].id);
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('❌ ERRO AO CRIAR PEDIDO:', error.message);
        res.status(500).json({ erro: 'Erro ao criar pedido' });
    }
});

// Meus pedidos
app.get('/api/meus-pedidos', autenticarToken, async (req, res) => {
    try {
        const userId = req.usuario.id;
        
        const result = await pool.query(
            'SELECT * FROM pedidos WHERE user_id = $1 ORDER BY created_at DESC',
            [userId]
        );

        res.json(result.rows);
    } catch (error) {
        console.error('❌ ERRO AO BUSCAR PEDIDOS:', error.message);
        res.status(500).json({ erro: 'Erro ao buscar pedidos' });
    }
});

// ==================== PAGAMENTO MERCADO PAGO ====================

// Criar preferência de pagamento
app.post('/api/pagamento-multiplo', async (req, res) => {
    try {
        const { cart } = req.body;
        
        console.log(' Recebido pedido de pagamento:', cart);

        if (!cart || cart.length === 0) {
            return res.status(400).json({ erro: 'Carrinho vazio' });
        }

        const items = cart.map(item => ({
            title: item.nome,
            quantity: item.quantidade || 1,
            unit_price: Number(item.preco),
            currency_id: 'BRL'
        }));

        const body = {
            items: items,
            back_urls: {
                success: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/sucesso`,
                failure: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/falha`,
                pending: `${process.env.FRONTEND_URL || 'https://dropsetnutri.netlify.app'}/pendente`
            },
            auto_return: 'approved'
        };

        const preference = new Preference(client);
        const response = await preference.create({ body });
        
        console.log('✅ Pagamento gerado:', response.id);
        res.json({ 
            id: response.id,
            link: response.init_point
        });
    } catch (error) {
        console.error('❌ ERRO MP:', error.message);
        res.status(500).json({ 
            erro: 'Erro ao gerar pagamento',
            details: error.message
        });
    }
});

// Webhook do Mercado Pago
app.post('/api/webhook-mp', async (req, res) => {
    try {
        const { data, type } = req.body;

        if (type === 'payment') {
            const payment = await mercadopago.payment.get(data.id);
            const paymentData = payment.body;
            
            const status = paymentData.status;
            
            await pool.query(
                'UPDATE pedidos SET status = $1, pagamento_id = $2 WHERE pagamento_id = $3',
                [status, paymentData.id, paymentData.order_id]
            );

            console.log(`💰 Pagamento ${paymentData.id} atualizado para: ${status}`);
        }

        res.status(200).send('OK');
    } catch (error) {
        console.error('❌ ERRO WEBHOOK:', error.message);
        res.status(500).send('Erro');
    }
});

// ==================== INICIALIZAÇÃO ====================

app.listen(PORT, () => {
    console.log('🔥 Servidor DropSet ativo na porta', PORT);
    console.log('📡 Rotas disponíveis: /api/registro, /api/login, /api/produtos, /api/pagamento-multiplo');
    console.log('🏦 Mercado Pago configurado com nova API');
});

module.exports = app;