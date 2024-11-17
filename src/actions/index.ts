import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";
import { defineAction } from "astro:actions";
import { z } from "astro:schema";

export const server = {
  options: defineAction({
    accept: "form",
    input: z.object({
      username: z.string(),
    }),
    handler: async (input, context) => {
      const session = context.cookies.get("session")?.json() || {};
      const username = input.username;
      const options = await generateRegistrationOptions({
        rpName: "Vault",
        rpID: import.meta.env.RP,
        userID: new Uint8Array(Buffer.from(username)),
        userName: username,
        attestationType: "indirect",
        authenticatorSelection: {
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7, -257],
      });

      session.challenge = options.challenge;
      session.user = username;

      context.cookies.set("session", JSON.stringify(session), {
        path: "/",
        httpOnly: true,
        secure: import.meta.env.PROD,
        sameSite: "strict",
        maxAge: 60 * 60 * 24,
      });

      return options;
    },
  }),
  verify: defineAction({
    input: z.object({
      attestationResponse: z.any(),
    }),
    handler: async (input, context) => {
      const session = context.cookies.get("session")?.json() || {};

      const attestationResponse: RegistrationResponseJSON =
        input.attestationResponse;
      const { challenge: expectedChallenge } = session;

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: attestationResponse,
          expectedChallenge,
          expectedOrigin: `https://${import.meta.env.RP}`,
          expectedRPID: import.meta.env.RP,
        });
      } catch (error: any) {
        return { succes: false, error: error.message };
      }

      if (!verification.verified) throw new Error("Verification failed!");

      // const { credentialID, credentialPublicKey } =
      //   verification.registrationInfo;
      // const credential = {
      //   id: credentialID,
      //   publicKey: Buffer.from(credentialPublicKey).toString("base64"),
      // };
      // const newUser = { username, credential };

      // TODO: store the user + credential in the database
      // session.user = { username };

      return {
        success: true,
      };
    },
  }),
};
