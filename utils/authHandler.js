const jwt = require('jsonwebtoken');
const userController = require('../controllers/users');

function normalizeRoleName(roleName) {
    if (!roleName) return '';
    const value = String(roleName).trim().toLowerCase();
    if (value === 'moderator') return 'mod';
    return value;
}

module.exports = {
    checkLogin: async function (req, res, next) {
        try {
            let token;

            if (req.cookies && req.cookies.token) {
                token = req.cookies.token;
            } else {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return res.status(403).send({ message: 'ban chua dang nhap' });
                }
                token = authHeader.split(' ')[1];
            }

            const result = jwt.verify(token, 'secret');
            req.userId = result.id;
            return next();
        } catch (error) {
            return res.status(403).send({ message: 'ban chua dang nhap' });
        }
    },

    checkRole: function (...requiredRoles) {
        const normalizedRequiredRoles = requiredRoles.map(normalizeRoleName);

        return async function (req, res, next) {
            try {
                const user = await userController.FindUserById(req.userId);
                if (!user || !user.role) {
                    return res.status(403).send({ message: 'ban khong co quyen' });
                }

                const currentRole = normalizeRoleName(user.role.name);
                if (normalizedRequiredRoles.includes(currentRole)) {
                    return next();
                }

                return res.status(403).send({ message: 'ban khong co quyen' });
            } catch (error) {
                return res.status(403).send({ message: 'ban khong co quyen' });
            }
        };
    }
};
