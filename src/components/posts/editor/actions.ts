"use server";

import { validateRequest } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { createPostSchema } from "@/lib/validation";

export async function submitPost(input: string) {
  const { user } = await validateRequest();

  if (!user) {
    throw new Error("Unauthorized");
  }

  const { content } = createPostSchema.parse({ content: input });

  //push to db
  await prisma.post.create({
    data: {
      content,
      userId: user.id, 
    },
  });
}
