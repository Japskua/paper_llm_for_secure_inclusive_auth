# ./Dockerfile
FROM oven/bun:1.3

# Path to the app.ts inside the repo, e.g.
# password_recovery_education/case_1_multi_no_condition_no_inclusion/app.ts
ARG APP_PATH
ENV APP_PATH=${APP_PATH}

WORKDIR /app

# Copy only the single-file app (they’re self-contained)
# If some apps import local modules, switch to `COPY . .` and use APP_PATH at runtime.
COPY ${APP_PATH} /app/app.ts

# Your code serves HTTP on 3000 and HTTPS on 3443
EXPOSE 3000 3441 3442 3443 8441 8442 8443

# Run exactly the same single-file app
CMD ["bun", "run", "app.ts"]