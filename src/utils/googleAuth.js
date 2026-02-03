import "../config/env.js";
import { OAuth2Client } from "google-auth-library";

export const getGoogleClient = () => {
	const clientId = process.env.GOOGLE_CLIENT_ID;
	const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
	const redirectUri =
		process.env.NODE_ENV === "production"
			? process.env.GOOGLE_REDIRECT_URI
			: "http://localhost:3000/auth/google/callback";

	if (!clientId || !clientSecret) {
		throw new Error("Google OAuth credentials are missing");
	}

	return new OAuth2Client({
		clientId,
		clientSecret,
		redirectUri,
	});
};
