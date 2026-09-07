FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy application source code and initial data
COPY . .

# Set environment variables for local container execution
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=3000

# Expose server port
EXPOSE 3000

# Run the application
CMD ["npm", "start"]
