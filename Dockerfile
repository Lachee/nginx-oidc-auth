FROM node:24-alpine

WORKDIR /app
RUN npm install -g pnpm

COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# Copy the source code
COPY src/ ./src/
COPY tsconfig.json ./

# Build the app
RUN pnpm run build

# Remove development dependencies to reduce image size
# RUN pnpm install --prod --frozen-lockfile

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Change ownership of the app directory to the nodejs user
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose the port the app runs on
EXPOSE 3600
ENV NODE_ENV=production
ENV PORT=3600

# Command to run the application
CMD ["node", "dist/index.js"]
