var bcrypt =require('bcrypt')

module.exports = (sequelize, Sequelize) => {
    const User = sequelize.define("user", {
      email: {
        type: Sequelize.STRING
      },
      password: {
        type: Sequelize.STRING
      }
    });

    User.beforeCreate(async User => {
      // eslint-disable-next-line no-param-reassign
      User.password = await User.generatePasswordHash();
    });
  
    
    User.prototype.generatePasswordHash = async function generatePasswordHash() {
      const saltRounds = 8;
      return bcrypt.hash(this.password, saltRounds);
    };
  
    User.prototype.validatePassword = async function validatePassword(password) {
      return bcrypt.compare(password, this.password);
    };
  
    User.prototype.getSafeDataValues = function getSafeDataValues() {
      const { password, ...data } = this.dataValues;
      return data;
    };
  
  
    return User;
  };