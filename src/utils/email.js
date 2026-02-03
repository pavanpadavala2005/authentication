// import "../config/env.js";
import nodemailer from "nodemailer";

export const sendEmail = async (to, subject, html) => {
	if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
		console.log("Gmail SMTP configuration is missing");
		return;
	}

	const transporter = nodemailer.createTransport({
		host: "smtp.gmail.com",
		port: 587,
		secure: false,
		auth: {
			user: process.env.GMAIL_USER,
			pass: process.env.GMAIL_APP_PASSWORD,
		},
		pool: true,
		maxConnections: 5,
		maxMessages: 100,
	});

	await transporter.sendMail({
		from: `"My App" <nodeAppTesting@gmail.com>`,
		to,
		subject,
		html,
	});
};
