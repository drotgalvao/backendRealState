export class AuthValidator {
    static areRequiredFieldsFilled(username, name, email, password, confirmPassword) {
        if (!username) {
            throw new Error('Username is required');
        }
    
        if (!name) {
            throw new Error('Name is required');
        }
    
        if (!email) {
            throw new Error('Email is required');
        }
    
        if (!password) {
            throw new Error('Password is required');
        }
    
        if (!confirmPassword) {
            throw new Error('Confirm Password is required');
        }
    }
    
    static doPasswordsMatch(password, confirmPassword) {
        if (password !== confirmPassword) {
            throw new Error('Passwords do not match!');
        }
    }

    static isStrongPassword(password) {
        if (!this.isAtLeast8Characters(password)) {
            throw new Error('Password must be at least 8 characters long');
        }

        if (!this.hasUppercaseLetter(password)) {
            throw new Error('Password must include at least one uppercase letter');
        }

        if (!this.hasLowercaseLetter(password)) {
            throw new Error('Password must include at least one lowercase letter');
        }

        if (!this.hasNumber(password)) {
            throw new Error('Password must include at least one number');
        }

        if (!this.hasSpecialCharacter(password)) {
            throw new Error('Password must include at least one special character');
        }
    }
    

    static isValidEmailFormat(email) {
        const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
        if (!emailRegex.test(email)) {
            throw new Error('Invalid email format');
        }
    }

    static async isUsernameUnique(username, User) {
        const existingUserWithUsername = await User.findOne({ username });
        if (existingUserWithUsername) {
            throw new Error('Username already exists');
        }
    }

    static async isEmailUnique(email, User) {
        const existingUserWithEmail = await User.findOne({ email });
        if (existingUserWithEmail) {
            throw new Error('Email already exists');
        }
    }

    static isAtLeast8Characters(password) {
        return password.length >= 8;
    }

    static hasUppercaseLetter(password) {
        const uppercaseRegex = /[A-Z]/;
        return uppercaseRegex.test(password);
    }

    static hasLowercaseLetter(password) {
        const lowercaseRegex = /[a-z]/;
        return lowercaseRegex.test(password);
    }

    static hasNumber(password) {
        const numberRegex = /\d/;
        return numberRegex.test(password);
    }

    static hasSpecialCharacter(password) {
        const specialCharRegex = /[!@#$%;*(){}_+^&]/;
        return specialCharRegex.test(password);
    }
    
    
}
