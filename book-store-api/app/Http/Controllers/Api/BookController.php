<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\BookRequest;
use App\Http\Resources\BookResource;
use App\Models\Book;
use Illuminate\Http\JsonResponse;
use Illuminate\Pagination\LengthAwarePaginator;

class BookController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return LengthAwarePaginator
     */
    public function index(): LengthAwarePaginator
    {
        return Book::paginate(4);
    }

    /**
     *  Store a newly created resource in storage.
     *
     * @param BookRequest $request
     * @return JsonResponse
     */
    public function store(BookRequest $request): JsonResponse
    {
        $data = $request->validated();
        $book = Book::create($data);

        return response()->json(BookResource::make($book), 201);
    }

    /**
     * Display the specified resource.
     *
     * @param Book $book
     * @return JsonResponse
     */
    public function show(Book $book): JsonResponse
    {
        return response()->json(BookResource::make($book), 200);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param BookRequest $request
     * @param Book $book
     * @return JsonResponse
     */
    public function update(BookRequest $request, Book $book): JsonResponse
    {
        $data = $request->validated();
        $book->update($data);

        return response()->json(BookResource::make($book), 201);
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param Book $book
     * @return JsonResponse
     * @throws \Throwable
     */
    public function destroy(Book $book): JsonResponse
    {
        $book->deleteOrFail();

        return response()->json(['message' => 'Book successfully deleted'], 200);
    }
}
