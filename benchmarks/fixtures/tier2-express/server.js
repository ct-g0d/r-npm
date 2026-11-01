const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

app.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'tier2-express' });
});

module.exports = app;

if (require.main === module) {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server listening on port ${port}`);
    });
}
