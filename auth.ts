import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const signUp = async (data: FormData) => {
  console.log('Sign Up Data:', data);

  if (await getUser(data.get('email')?.toString() || '')) {
    console.log('User already exists.');
    await signIn('credentials', data);
  } else {
    try {
      const email = data.get('email')?.toString();
      const name = email?.replace('.', ' ').substring(0, email.indexOf('@'));
      const password = data.get('password')?.toString();

      const parsedCredentials = z
        .object({ email: z.string().email(), password: z.string().min(6) })
        .safeParse({ email, password });

      console.log('Name:', name);
      console.log('Email:', email);
      console.log('Password:', password);

      console.log('Parsed Credentials:', parsedCredentials);

      if (password != undefined) {
        const hashedPassword = await bcrypt.hash(password, 10);

        if (parsedCredentials.success) {
          const user = await sql<User>`INSERT INTO users
    (name, email, password) VALUES
      (${name}, ${email}, ${hashedPassword}) RETURNING *`;
        } else {
          throw new Error('Invalid credentials.');
        }
      }
    } catch (error) {
      console.error('Failed to create user:', error);
    }

    await signIn('credentials', data);
  }
};

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        console.log('Parsed Credentials Authorized:', parsedCredentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);

          if (passwordsMatch) return user;
        }

        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
