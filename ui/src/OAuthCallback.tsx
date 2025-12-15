import { useEffect, useState } from "react";
import { useSearchParams, useNavigate, useParams } from "react-router";
import { AccountApi } from "./api";
import { CircularProgress, Container, Typography, Box } from "@mui/material";
import { User } from "./model/user.ts";

interface OAuthCallbackProps {
    onLogin: (user: User) => void;
}

const OAuthCallback = ({ onLogin }: OAuthCallbackProps) => {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { provider } = useParams();
    const [error, setError] = useState<string>("");

    useEffect(() => {
        const code = searchParams.get("code");
        const state = searchParams.get("state");
        const errorParam = searchParams.get("error");

        if (errorParam) {
            console.error("OAuth error:", errorParam);
            setError(`OAuth authentication failed: ${errorParam}`);
            setTimeout(() => navigate("/login?error=oauth_failed"), 3000);
            return;
        }

        if (!code || !state) {
            setError("Invalid OAuth callback - missing code or state");
            setTimeout(() => navigate("/login?error=invalid_callback"), 3000);
            return;
        }

        if (!provider) {
            setError("Invalid OAuth callback - missing provider");
            setTimeout(() => navigate("/login?error=invalid_callback"), 3000);
            return;
        }

        // Exchange code for account token
        new AccountApi().oauthCallback({
            provider: provider,
            code: code,
            state: state
        })
            .then(response => {
                if (response.accountToken && response.email) {
                    onLogin({
                        email: response.email,
                        token: response.accountToken
                    });
                    navigate("/");
                } else {
                    setError("Invalid response from server");
                    setTimeout(() => navigate("/login?error=oauth_failed"), 3000);
                }
            })
            .catch(err => {
                console.error("OAuth callback error:", err);
                setError("Authentication failed. Please try again.");
                setTimeout(() => navigate("/login?error=oauth_failed"), 3000);
            });
    }, [searchParams, navigate, onLogin, provider]);

    return (
        <Container maxWidth="xs" sx={{ textAlign: "center", mt: 8 }}>
            {error ? (
                <Box>
                    <Typography variant="h6" color="error" sx={{ mb: 2 }}>
                        {error}
                    </Typography>
                    <Typography variant="body2">
                        Redirecting to login...
                    </Typography>
                </Box>
            ) : (
                <Box>
                    <CircularProgress />
                    <Typography sx={{ mt: 2 }}>
                        Completing authentication...
                    </Typography>
                </Box>
            )}
        </Container>
    );
};

export default OAuthCallback;
