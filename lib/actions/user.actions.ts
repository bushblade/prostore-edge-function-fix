'use server';

import {
  paymentMethodSchema,
  shippingAddressSchema,
  signInFormSchema,
  signUpFormSchema,
} from '../validators';
import { auth, signIn, signOut } from '@/auth';
import { isRedirectError } from 'next/dist/client/components/redirect-error';
//import { hashSync } from 'bcrypt-ts-edge';
import { compare, hash } from '@/lib/encrypt';

import { prisma } from '@/db/prisma';
import { formatError } from '@/lib/utils';
import { ShippingAddress } from '@/types';
import { z } from 'zod';

// Sign in the user with credentials
export async function signInWithCredentials(
  prevState: unknown,
  formData: FormData
) {
  try {
    const { email, password } = signInFormSchema.parse({
      email: formData.get('email'),
      password: formData.get('password'),
    });

    let user = await prisma.user.findFirst({
      where: {
        email,
      },
    });
    if (!user) throw new Error('No user found');

    const isMatch = await compare(password, user.password as string);
    if (!isMatch) throw new Error('Incorrect password');

    if (user.name === 'NO_NAME') {
      user = await prisma.user.update({
        where: { id: user.id },
        data: { name: user.email.split('@')[0] },
      });
    }

    await signIn('credentials', {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    });
    return { success: true, message: 'Signed in successfully' };
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }
    return { success: false, message: 'Invalid email or password' };
  }
}

// Sign out user
export async function signOutUser() {
  await signOut();
}

// Sign up user
export async function signUpUser(prevState: unknown, formData: FormData) {
  try {
    const userInfo = signUpFormSchema.parse({
      name: formData.get('name'),
      email: formData.get('email'),
      password: formData.get('password'),
      confirmPassword: formData.get('confirmPassword'),
    });
    userInfo.password = await hash(userInfo.password);

    const user = await prisma.user.create({
      data: {
        name: userInfo.name,
        email: userInfo.email,
        password: userInfo.password,
      },
    });
    await signIn('credentials', {
      email: user.email,
      id: user.id,
      name: user.name,
      role: user.role,
    });

    return { success: true, message: 'User registered successfully' };
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }
    return { success: false, message: formatError(error) };
  }
}

// Get user by the ID
export async function getUserById(userId: string) {
  const user = await prisma.user.findFirst({
    where: {
      id: userId,
    },
  });
  if (!user) throw new Error('User not found');
  return user;
}

// update user address
export async function updateUserAddress(data: ShippingAddress) {
  try {
    const session = await auth();
    const currentUser = await prisma.user.findFirst({
      where: { id: session?.user?.id },
    });
    if (!currentUser) throw new Error('User not found');
    const address = shippingAddressSchema.parse(data);
    await prisma.user.update({
      where: { id: currentUser.id },
      data: { address },
    });
    return { success: true, message: 'User updated successfully' };
  } catch (error) {
    return { success: false, message: formatError(error) };
  }
}

// update user's payment method
export async function updateUserPaymentMethod(
  data: z.infer<typeof paymentMethodSchema>
) {
  try {
    const session = await auth();
    const currentUser = await prisma.user.findFirst({
      where: { id: session?.user?.id },
    });
    if (!currentUser) throw new Error('User not found');
    const paymentMethod = paymentMethodSchema.parse(data);

    await prisma.user.update({
      where: { id: currentUser.id },
      data: {
        paymentMethod: paymentMethod.type,
      },
    });
    return { success: true, message: 'User updated successfully' };
  } catch (error) {
    return { success: false, message: formatError(error) };
  }
}
