
# Agile Plan – Inventory App Project

This Agile plan outlines the sprint structure, milestones, epics, and user stories for the development of the Inventory App using Scrum methodology.

---

## 1. Project Overview

- **Project Name**: Inventory Management App
- **Team**: Full-stack developers, UI/UX designer, QA, Product Owner
- **Duration**: 6 Weeks
- **Sprints**: 3 sprints (2 weeks each)

---

## 2. Milestones

| Milestone                | Description                           | Target Date     |
|--------------------------|---------------------------------------|------------------|
| Project Kickoff          | Requirements finalized, backlog ready | Week 1, Day 1    |
| Sprint 1 Completion      | Backend + API, basic web UI           | End of Week 2    |
| Sprint 2 Completion      | Mobile screens + web modals           | End of Week 4    |
| Final Sprint Completion  | Full CRUD on both platforms + QA pass | End of Week 6    |
| Deployment & Wrap-Up     | Production deploy, docs complete      | End of Week 6    |

---

## 3. Epics

### Epic 1: Backend API & Database
- Set up Express server and MongoDB connection
- Define Mongoose models and schema
- Implement CRUD routes

### Epic 2: Web Frontend (Vue.js)
- HomePage with item list
- AddItem and EditItem modals
- API integration using Axios

### Epic 3: Mobile Frontend (React Native)
- HomePage screen
- AddItem and EditItem screens
- Shared API integration

### Epic 4: User Experience & QA
- Error handling, form validation
- Undo delete support
- Manual testing on multiple devices
- Documentation and SRS review

---

## 4. Sprint Breakdown

### Sprint 1: Foundation & Web CRUD

**Goals**
- Set up backend API
- Basic frontend for viewing and adding items

**Stories**
- [ ] Set up Express server and routes
- [ ] Create Item model in Mongoose
- [ ] Implement `GET`, `POST`, `DELETE` routes
- [ ] Create HomePage.vue with item table
- [ ] Add AddItemModal.vue with form

---

### Sprint 2: Mobile UI & Web Editing

**Goals**
- Develop core mobile features
- Enable item editing on web

**Stories**
- [ ] Create HomePage.js for React Native
- [ ] Add AddItem.js and EditItem.js
- [ ] Build EditItemModal.vue with update/delete
- [ ] Implement shared Axios module for both platforms

---

### Sprint 3: Testing, Polish & Deployment

**Goals**
- Polish UI/UX
- Finalize undo, error handling, and responsiveness
- Deploy and document

**Stories**
- [ ] Implement undo delete functionality
- [ ] Add error toasts on failed API calls
- [ ] Finalize styles and layout on web/mobile
- [ ] Seed database with test items
- [ ] Write and export design & requirements docs
- [ ] Deploy backend and frontend to production

---

## 5. Tools

- **Task Management**: Trello / Jira
- **Version Control**: Git (GitHub or GitLab)
- **Deployment**: Vercel / Netlify (web), Expo / EAS (mobile)
- **Documentation**: Markdown + PDF export

---

**Product Owner**: _TBD_  
**Scrum Master**: _TBD_  
**Date Prepared**: 2025-05-15
