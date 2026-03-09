let bcrypt = require('bcrypt');
let userModel = require('../schemas/users')
module.exports = {
    CreateAnUser: async function (username, password, email, role,
        avatarUrl, fullName, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            role: role,
            avatarUrl: avatarUrl,
            fullName: fullName,
            status: status,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    QueryByUserNameAndPassword: async function (username, password) {
        let getUser = await userModel.findOne({ username: username });
        if (!getUser) {
            return false;
        }
        const isCorrectPassword = bcrypt.compareSync(password, getUser.password);
        if (!isCorrectPassword) {
            return false;
        }

        return getUser;
    },
    FindUserById: async function (id) {
        return await userModel.findOne({
            _id: id,
            isDeleted:false
        }).populate('role')
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        const user = await userModel.findOne({ _id: userId, isDeleted: false });
        if (!user) {
            return { ok: false, status: 404, message: 'khong tim thay user' };
        }

        const isCorrectPassword = bcrypt.compareSync(oldPassword, user.password);
        if (!isCorrectPassword) {
            return { ok: false, status: 400, message: 'oldPassword khong dung' };
        }

        user.password = newPassword;
        await user.save();

        return { ok: true, message: 'doi mat khau thanh cong' };
    }
}
