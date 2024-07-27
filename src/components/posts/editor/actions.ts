"use server";

import { validateRequest } from "@/lib/auth";
import prisma from "@/lib/prisma";
import { postDataInclude } from "@/lib/types";
import { createPostSchema } from "@/lib/validation";

export async function submitPost(input: string) {
  const { user } = await validateRequest();

  if (!user) {
    throw new Error("Unauthorized");
  }

  const { content } = createPostSchema.parse({ content: input });

  //push to db
  const newPost = await prisma.post.create({
    data: {
      content,
      userId: user.id,
    },
    include: postDataInclude,
  });

  return newPost;
}
